use std::collections::{BTreeMap, BTreeSet};

use uuid::Uuid;

use crate::ref_store::contract::RequestDigest;
use crate::ref_store::core::state_machine::{
    AppliedLogId, BeginOperationCommand, CommitRefsCommand, InitializeGateCommand, RefCasCommand, RefCasStateMachine,
    RepositoryLane, ScopeLifecycle, SmPackMode, WireCommitRefsRequest, WireGateInit, WireOperationIdentity,
};
use crate::ref_store::{
    CommitMode, CommitRefsRequest, CoreGateInit, GitObjectFormat, GitOid, HeadUpdate, IssuerLane, RefName,
    RefPrecondition, RefTarget, RefUpdate,
};

use super::freeze_drain::{InFlightOperation, RepoBackupRegistrationSpec, TriPartyBackupCoordinator};
use super::git_verify::{seed_commit_pack, verify_bare_repo_from_blobs};
use super::restore::IncarnationAdmissionGuard;
use super::types::{
    BlobArtifactEntry, BlobClosureManifest, CloseScopeBarrierReceipt, DecisionExecutionTicket, DeleterLeaseTicket,
    FreezePartyStatus, NewIncarnationAuthority, PAIRED_BACKUP_FORMAT_V1, PairedBackupError, PairedBackupManifest,
    PgCutpointProof, PgProjectionCursorCut, PgRepositoryRowProof, RaftCutpointProof, WriterGrantTicket,
    sha256_json_tagged,
};

fn seed_open_sm(repo: Uuid, tenant: Uuid, issuer: Uuid, history: Uuid) -> (RefCasStateMachine, u64, String, String) {
    let mut sm = RefCasStateMachine::new();
    let head = RefName::branch("refs/heads/main").expect("branch");
    let init = CoreGateInit::new(repo, tenant, GitObjectFormat::Sha256, history, 2, 3, head).expect("gate");
    sm.apply(
        AppliedLogId { term: 1, index: 1 },
        RefCasCommand::InitializeGate(InitializeGateCommand {
            gate: WireGateInit::from(&init),
            pack_mode: SmPackMode::MetadataOnly,
            lane: RepositoryLane::ServingRefStore,
            authz_floor: 5,
        }),
    )
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
        lane.clone(),
        1,
        Uuid::new_v4(),
        GitObjectFormat::Sha256,
        history,
        2,
        3,
        1,
        HeadUpdate::Keep,
        CommitMode::Atomic,
        vec![upd],
    )
    .expect("req");
    sm.apply(
        AppliedLogId { term: 1, index: 2 },
        RefCasCommand::CommitRefs(CommitRefsCommand {
            request: WireCommitRefsRequest::from(&req),
            decision_id: None,
            required_holds: Vec::new(),
            policy_rejects: BTreeMap::new(),
            logical_tick: 10,
        }),
    )
    .expect("commit");
    let _ = lane;
    (sm, 2, commit_hex, RequestDigest::of("pack-digest", &[repo.as_bytes()]).as_hex())
}

#[test]
fn tri_party_freeze_enforces_unknown_drain_and_holds_before_unfreeze() {
    let (repo, tenant, issuer, history, auth_id) =
        (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let (mut sm, mut log_idx, _commit_hex, pack_digest) = seed_open_sm(repo, tenant, issuer, history);

    let pending_op = Uuid::new_v4();
    let op_digest = RequestDigest::of("pending-op", &[pending_op.as_bytes()]).as_hex();
    let lane = IssuerLane::new("pack").expect("lane");
    log_idx += 1;
    sm.apply(
        AppliedLogId { term: 1, index: log_idx },
        RefCasCommand::BeginOperation(BeginOperationCommand {
            identity: WireOperationIdentity {
                repository_id: repo,
                issuer_id: issuer,
                lane: lane.as_str().to_owned(),
                sequence: 2,
                operation_id: pending_op,
                digest: op_digest.clone(),
            },
            logical_tick: 11,
        }),
    )
    .expect("begin op");

    let mut coord = TriPartyBackupCoordinator::new(10, 4);
    assert!(coord.admit_app_write().is_ok());
    assert!(coord.admit_worker_lease().is_ok());
    assert!(coord.admit_deleter(10).is_ok());
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

    assert!(matches!(coord.unfreeze_after_backup(), Err(PairedBackupError::IncompleteCut(_))));

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
        backend_identity: RequestDigest::of("backend", &[auth_id.as_bytes()]).as_hex(),
        pack_digests: vec![pack_digest.clone()],
        hold_specs: vec![(pack_digest, 2048, 512)],
    }];

    let err = coord.freeze_drain_and_register(&mut sm, 1, &mut log_idx, &specs, 12, false).unwrap_err();
    assert!(matches!(err, PairedBackupError::UnknownInFlightOperations(1)));

    let receipts = coord.freeze_drain_and_register(&mut sm, 1, &mut log_idx, &specs, 12, true).expect("drain ok");
    assert_eq!(receipts.len(), 2);
    for r in &receipts {
        r.verify().expect("valid receipt");
        assert_eq!(r.lifecycle, ScopeLifecycle::Closed);
        assert!(r.open_decision_ids.is_empty());
        assert!(r.pending_operation_ids.is_empty());
    }
    assert!(sm.has_cancel_tombstone(repo, pending_op));
    coord.status().require_frozen().expect("frozen while Raft active");
    assert!(coord.admit_app_write().is_err());
    assert!(coord.admit_worker_lease().is_err());
    assert!(coord.admit_deleter(11).is_err());

    coord.unfreeze_after_backup().expect("unfreeze after holds");
    assert!(coord.admit_app_write().is_ok());
    assert!(coord.admit_deleter(10).is_err());
    assert!(coord.admit_deleter(coord.status().fenced_deleter_epoch).is_ok());
}

#[test]
fn manifest_digest_tamper_and_incarnation_guard_refuse_stale_credentials() {
    let (repo, tenant, issuer, history, auth_id) =
        (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let (mut sm, mut log_idx, commit_hex, pack_digest) = seed_open_sm(repo, tenant, issuer, history);
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
        pack_digests: vec![pack_digest.clone()],
        hold_specs: vec![(pack_digest.clone(), 4096, 512)],
    }];
    let mut coord = TriPartyBackupCoordinator::new(3, 1);
    let receipts = coord.freeze_drain_and_register(&mut sm, 1, &mut log_idx, &specs, 15, true).expect("freeze");
    let snap = sm.snapshot().expect("snap");
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
        pending_decisions_count: 0,
        pending_outbox_count: 0,
        projection_cursors: vec![PgProjectionCursorCut {
            group_id: 1,
            history_incarnation: history,
            group_epoch: 3,
            applied_event_seq: snap.body.next_event_seq.saturating_sub(1) as i64,
            applied_log_index: log_idx as i64,
            applied_log_term: 1,
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
        total_artifacts: 1,
        total_bytes: 4096,
        entries: vec![BlobArtifactEntry {
            repository_id: repo,
            tenant_id: tenant,
            pack_id: Uuid::new_v4(),
            object_format: GitObjectFormat::Sha256,
            role: "pack".into(),
            locator_path: "blobs/pack".into(),
            archive_rel_path: "blobs/pack".into(),
            attempt_id: Uuid::new_v4(),
            generation: 1,
            length: 4096,
            sha256: pack_digest,
            backend_identity: backend,
        }],
        closure_digest: String::new(),
    }
    .seal()
    .expect("closure");

    let manifest = PairedBackupManifest {
        format_version: PAIRED_BACKUP_FORMAT_V1.into(),
        backup_id: Uuid::new_v4(),
        created_unix_seconds: 1_760_000_000,
        freeze: FreezePartyStatus {
            app_paused: true,
            worker_paused: true,
            deleter_fenced: true,
            consensus_replication_active: true,
            leader_election_active: true,
            fenced_deleter_epoch: 4,
            app_fence_seq: 2,
            worker_drain_settled: 0,
            unknown_ops_resolved: 0,
        },
        pg_cutpoint: pg.clone(),
        raft_cutpoint: RaftCutpointProof {
            group_id: 1,
            applied_log_id: AppliedLogId { term: 1, index: log_idx },
            logical_clock_floor: sm.logical_clock_floor(),
            state_digest: sm.state_digest().expect("sd"),
            group_membership_digest: "b".repeat(64),
            snapshot_checksum: snap.checksum.clone(),
            snapshot: snap,
            close_receipts: receipts,
            backup_holds: coord.registered_holds().to_vec(),
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

    let new_cluster = Uuid::new_v4();
    let new_auth = Uuid::new_v4();
    let new_hist = Uuid::new_v4();
    let fenced_dec = Uuid::new_v4();
    let guard = IncarnationAdmissionGuard {
        live: NewIncarnationAuthority {
            new_cluster_incarnation: new_cluster,
            new_storage_authority_id: new_auth,
            new_storage_generation: 2,
            new_history_incarnation: new_hist,
            new_authority_epoch: 3,
            new_group_epoch: 4,
            new_authz_floor: 25,
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
                authz_epoch: 25,
            })
            .is_ok()
    );
    assert!(matches!(
        guard.verify_writer_grant(&WriterGrantTicket {
            cluster_incarnation: pg.source_cluster_incarnation,
            history_incarnation: new_hist,
            authority_epoch: 3,
            group_epoch: 4,
            authz_epoch: 25,
        }),
        Err(PairedBackupError::StaleIncarnation { .. })
    ));
    assert!(matches!(
        guard.verify_decision_execution(&DecisionExecutionTicket {
            decision_id: fenced_dec,
            history_incarnation: new_hist,
            authority_epoch: 3,
            group_epoch: 4,
            authz_epoch: 25,
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
fn git_verify_roundtrip_sha1_and_sha256_and_rejects_corrupt_pack() {
    for fmt in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let dir = tempfile::tempdir().expect("tempdir");
        let (commit, pack, idx) =
            seed_commit_pack(&dir.path().join("seed"), fmt, "hello.txt", b"paired-backup-payload\n", None)
                .expect("seed commit");
        let refs = BTreeMap::from([("refs/heads/main".to_owned(), commit)]);
        let n = verify_bare_repo_from_blobs(
            &dir.path().join("bare"),
            fmt,
            &refs,
            &[(pack.clone(), idx.clone())],
            &dir.path().join("clone"),
        )
        .expect("git fsck & clone pass");
        assert_eq!(n, 1);

        let corrupt_pack = dir.path().join("corrupt.pack");
        let mut bytes = std::fs::read(&pack).expect("read pack");
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        std::fs::write(&corrupt_pack, bytes).expect("write corrupt pack");
        assert!(
            verify_bare_repo_from_blobs(
                &dir.path().join("bare-bad"),
                fmt,
                &refs,
                &[(corrupt_pack, idx)],
                &dir.path().join("clone-bad"),
            )
            .is_err()
        );
    }
}
