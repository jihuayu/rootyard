//! Default-off staging, arm_digest fence, PG/Ref-CAS reconcile & anti-ABA unit tests (#122).

use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, Instant},
};

use uuid::Uuid;

use crate::ref_store::{
    CommitRefsRequest, IssuerLane,
    core::{
        contract::CommitMode,
        state_machine::{
            AppliedLogId, ApplyResponse, BeginOperationCommand, CommitRefsCommand, InitializeGateCommand,
            RefCasCommand, RefCasStateMachine, RepositoryLane, SmPackMode, WireCommitRefsRequest, WireGateInit,
        },
        types::{GitObjectFormat, GitOid, HeadUpdate, RefName, RefPrecondition, RefTarget, RefUpdate},
    },
};

use super::{
    SafeGcError,
    anti_aba::{AntiAbaKeyRegistry, KeyLifecycleState},
    domain::{ActiveDeleteFence, AuthorityRecord, CasCompactionPublish, UploadedCompactionPair},
    executor::{quarantine_abandoned_staging_without_delete, reclaim_abandoned_compaction_staging},
    model::{
        AuthorityLane, DecisionKind, DecisionState, GcMode, GlobalHoldEntry, GlobalHoldState, InFlightDecisionRecord,
        RetentionProducer, SafeGcArmReceipt, SafeGcObjectFormat,
    },
    pg_maintenance_dist::{
        FsSealedRefCasCutpointSource, RefCasCommitCutpointPublisher, RefCasCutpointSource,
        persist_refcas_cutpoint_snapshot,
    },
    refcas_cut::RefCasReconciledCut,
    safe_gc_refcas_cutpoint_path,
    store::DurableSafeGcAuthority,
    store_reconcile::PgReconciledBundle,
    tests::{RecordingDeleteBackend, oid, seed_fixture, sha},
};

#[tokio::test]
async fn default_off_blocks_abandoned_staging_deletes_until_explicitly_armed() {
    let (snap, arm, _) = seed_fixture(SafeGcObjectFormat::Sha1, false);
    let auth = snap.authority.clone();
    let old_id = snap.active_packs[0].pack_id;
    let authority = DurableSafeGcAuthority::in_memory(snap).unwrap();
    let (pk, ik) = authority.mint_compaction_keys(1, &sha("np"), &sha("ni")).unwrap();
    let op_id = Uuid::new_v4();
    let mut pack_loc = authority.snapshot().active_packs[0].pack_locator.clone();
    pack_loc.sha256 = sha("np");
    let mut idx_loc = authority.snapshot().active_packs[0].idx_locator.clone();
    idx_loc.sha256 = sha("ni");
    let pair = UploadedCompactionPair {
        pack_locator: pack_loc,
        idx_locator: idx_loc,
        pack_key: pk.clone(),
        idx_key: ik.clone(),
    };
    authority.record_staged_upload(op_id, &pair).unwrap();
    let drift = authority.cas_publish_compaction(CasCompactionPublish {
        op_id,
        group_id: "g1".into(),
        expected_incarnation_id: auth.incarnation_id,
        expected_incarnation_epoch: 1,
        expected_generation: auth.membership_generation + 99,
        expected_membership_digest: authority.snapshot().compute_membership_digest(),
        retired_pack_ids: vec![old_id],
        uploaded: pair,
        replacement_oids: vec![],
        equivalence_digest: sha("eq"),
    });
    assert!(matches!(drift, Err(SafeGcError::MembershipOrRootDrift(_))));
    authority.mark_staged_upload_abandoned(op_id).unwrap();
    assert_eq!(authority.snapshot().active_packs.len(), 1);

    // 1. Default-off (`DisabledByDefault`) MUST refuse abandoned staging provider deletes (`0` deletes)!
    let backend = RecordingDeleteBackend::default();
    let dl = Instant::now() + Duration::from_secs(5);
    let disabled_err = reclaim_abandoned_compaction_staging(&authority, &backend, None, dl).await;
    assert!(matches!(disabled_err, Err(SafeGcError::DestructiveGcDisabledByDefault)));
    assert!(backend.deleted.lock().unwrap().is_empty(), "default-off must perform 0 staging deletes");
    assert_eq!(quarantine_abandoned_staging_without_delete(&authority).unwrap(), 1);
    assert!(backend.deleted.lock().unwrap().is_empty());

    // 2. Armed SingleNodePg WITHOUT live PG fence (`None`) fails closed; rotating gc_epoch fences stale ticket!
    authority.set_gc_mode(GcMode::ArmedDestructive(arm)).unwrap();
    assert!(matches!(
        reclaim_abandoned_compaction_staging(&authority, &backend, None, dl).await,
        Err(SafeGcError::StaleDeleterFenced(_))
    ));
    let stale_tickets = authority.mint_staging_cleanup_tickets().unwrap();
    let arm_gc2 = SafeGcArmReceipt::seal(
        auth.tenant_id,
        auth.repo_id,
        auth.history_id,
        auth.incarnation_id,
        1,
        true,
        AuthorityLane::SingleNodePg {
            pg_authority_id: auth.repo_id,
            pg_tx_seq: 10,
            pg_gc_fence_epoch: 2,
            reader_barrier_epoch: 2,
        },
    )
    .unwrap();
    authority.rebind_pending_delete_live_pg_fence(2, arm_gc2).unwrap();
    let live_fence = || -> Result<(), SafeGcError> { Ok(()) };
    let stale_fence = ActiveDeleteFence::new(&authority, &stale_tickets[0], Some(&live_fence));
    assert!(matches!(stale_fence.verify_active_for_ticket(&stale_tickets[0]), Err(SafeGcError::StaleDeleterFenced(_))));
    let cleaned = reclaim_abandoned_compaction_staging(&authority, &backend, Some(&live_fence), dl).await.unwrap();
    assert_eq!(cleaned.deleted_keys.len(), 2);
    let after = authority.snapshot();
    assert!(after.key_registry.deleted_tombstones.contains(&pk.object_path));
    assert!(after.key_registry.deleted_tombstones.contains(&ik.object_path));
}

#[test]
fn reconciled_sql_and_sm_holds_and_decisions_clear_when_resolved_preserving_manual_holds() {
    let (snap, arm, _) = seed_fixture(SafeGcObjectFormat::Sha1, false);
    let ret_id = snap.retired_packs[0].pack_id;
    let authority = DurableSafeGcAuthority::in_memory(snap.clone()).unwrap();
    authority.set_gc_mode(GcMode::ArmedDestructive(arm.clone())).unwrap();
    let manual_hold_id = Uuid::new_v4();
    authority
        .upsert_global_hold(GlobalHoldEntry {
            hold_id: manual_hold_id,
            tenant_id: snap.authority.tenant_id,
            repo_id: snap.authority.repo_id,
            incarnation_epoch: 1,
            registered_seq: 1,
            state: GlobalHoldState::Active,
            protected_pack_ids: vec![],
            protected_oids: vec![],
            protected_physical_keys: vec![],
        })
        .unwrap();

    let sql_hold_id = Uuid::new_v4();
    let sql_dec_id = Uuid::new_v4();
    authority
        .apply_pg_reconciled_bundle(PgReconciledBundle {
            live_refs: snap.live_refs.clone(),
            max_ref_seq: 10,
            producers: snap.producers.clone(),
            cursors: snap.paired_cursors.clone(),
            sql_holds: vec![GlobalHoldEntry {
                hold_id: sql_hold_id,
                tenant_id: snap.authority.tenant_id,
                repo_id: snap.authority.repo_id,
                incarnation_epoch: 1,
                registered_seq: 1,
                state: GlobalHoldState::Active,
                protected_pack_ids: vec![ret_id],
                protected_oids: vec![],
                protected_physical_keys: vec![],
            }],
            sql_decisions: vec![InFlightDecisionRecord {
                decision_id: sql_dec_id,
                kind: DecisionKind::Push,
                state: DecisionState::Pending,
                snapshot_seq: 10,
                protected_pack_ids: vec![ret_id],
                protected_oids: vec![],
            }],
            transient_reads: vec![],
            pg_gc_fence_epoch: Some(1),
        })
        .unwrap();
    assert!(authority.build_authoritative_deletion_proof(arm.clone(), &[ret_id]).is_err());

    // Once PG resolves the decision & consumes the hold, next reconcile clears them while keeping manual_hold_id!
    authority
        .apply_pg_reconciled_bundle(PgReconciledBundle {
            live_refs: snap.live_refs.clone(),
            max_ref_seq: 10,
            producers: snap.producers,
            cursors: snap.paired_cursors,
            sql_holds: vec![],
            sql_decisions: vec![],
            transient_reads: vec![],
            pg_gc_fence_epoch: Some(1),
        })
        .unwrap();
    assert_eq!(authority.snapshot().global_holds.len(), 1);
    assert_eq!(authority.snapshot().global_holds[0].hold_id, manual_hold_id);
    assert!(authority.snapshot().in_flight_decisions.is_empty());
    assert!(authority.build_authoritative_deletion_proof(arm, &[ret_id]).is_ok());

    // Also verify apply_refcas_reconciled_cut clears resolved SM holds, decisions, and snapshot pin OIDs!
    let sm_pin = oid(SafeGcObjectFormat::Sha1, 9);
    let cut = RefCasReconciledCut {
        group_id: 0,
        group_epoch: 1,
        history_id: snap.authority.history_id,
        sm_applied_log_term: 1,
        sm_applied_log_index: 10,
        sm_applied_event_seq: 2,
        sm_last_event_log_term: 1,
        sm_last_event_log_index: 10,
        sm_snapshot_checksum: sha("sm"),
        pg_projected_log_term: 1,
        pg_projected_log_index: 10,
        pg_projected_event_seq: 2,
        unprojected_jobs_count: 0,
    };
    authority
        .apply_refcas_reconciled_cut(
            snap.live_refs.clone(),
            vec![sm_pin.clone()],
            vec![GlobalHoldEntry {
                hold_id: Uuid::new_v4(),
                tenant_id: snap.authority.tenant_id,
                repo_id: snap.authority.repo_id,
                incarnation_epoch: 1,
                registered_seq: 10,
                state: GlobalHoldState::Active,
                protected_pack_ids: vec![ret_id],
                protected_oids: vec![],
                protected_physical_keys: vec![],
            }],
            vec![InFlightDecisionRecord {
                decision_id: Uuid::new_v4(),
                kind: DecisionKind::Push,
                state: DecisionState::Pending,
                snapshot_seq: 10,
                protected_pack_ids: vec![ret_id],
                protected_oids: vec![],
            }],
            cut.clone(),
        )
        .unwrap();
    assert_eq!(authority.snapshot().global_holds.len(), 2);
    assert_eq!(authority.snapshot().in_flight_decisions.len(), 1);
    authority.apply_refcas_reconciled_cut(snap.live_refs, vec![], vec![], vec![], cut).unwrap();
    let after_sm = authority.snapshot();
    assert_eq!(after_sm.global_holds.len(), 1);
    assert_eq!(after_sm.global_holds[0].hold_id, manual_hold_id);
    assert!(after_sm.in_flight_decisions.is_empty());
    let ws_prod = after_sm.producers.iter().find(|p| p.producer == RetentionProducer::Workspace).unwrap();
    assert!(!ws_prod.root_oids.contains(&sm_pin));
}

#[test]
fn anti_aba_registry_forbids_reuse_even_after_deletion_and_same_sha_reupload() {
    let (t, r, h) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let same_sha = sha("identical-pack");
    let mut reg = AntiAbaKeyRegistry::new();
    let k1 = reg.mint_immutable_key((t, r, h, 1), "pack", &same_sha, KeyLifecycleState::ActiveServing).unwrap();
    reg.transition_state(&k1.object_path, KeyLifecycleState::ActiveServing, KeyLifecycleState::RetiredPendingProof)
        .unwrap();
    reg.transition_state(
        &k1.object_path,
        KeyLifecycleState::RetiredPendingProof,
        KeyLifecycleState::DeletePendingBarrier,
    )
    .unwrap();
    reg.transition_state(
        &k1.object_path,
        KeyLifecycleState::DeletePendingBarrier,
        KeyLifecycleState::PhysicallyDeletedTombstone,
    )
    .unwrap();

    let k2 = reg.mint_immutable_key((t, r, h, 1), "pack", &same_sha, KeyLifecycleState::ActiveServing).unwrap();
    assert_ne!(k1.object_path, k2.object_path);
    assert!(k2.allocation_seq > k1.allocation_seq);
    assert!(matches!(reg.register_verified_key(k1.clone()), Err(SafeGcError::AbaKeyReuseDetected(_))));
    assert!(matches!(reg.assert_late_put_allowed(&k1.object_path, 1), Err(SafeGcError::AbaKeyReuseDetected(_))));

    reg.advance_incarnation_epoch(2).unwrap();
    assert!(matches!(reg.assert_late_put_allowed(&k2.object_path, 1), Err(SafeGcError::StaleIncarnation(_))));
    assert!(matches!(reg.assert_delete_allowed(&k2.object_path, 1), Err(SafeGcError::StaleDeleterFenced(_))));
    let unique: BTreeSet<_> = [k1.object_path, k2.object_path].into_iter().collect();
    assert_eq!(unique.len(), 2);
}

#[test]
fn refcas_cut_rejects_event_seq_off_by_one_against_pg_projection() {
    let history_id = Uuid::new_v4();
    let base = RefCasReconciledCut {
        group_id: 0,
        group_epoch: 1,
        history_id,
        sm_applied_log_term: 1,
        sm_applied_log_index: 3,
        sm_applied_event_seq: 1,
        sm_last_event_log_term: 1,
        sm_last_event_log_index: 3,
        sm_snapshot_checksum: sha("sm-cut"),
        pg_projected_log_term: 1,
        pg_projected_log_index: 3,
        pg_projected_event_seq: 0,
        unprojected_jobs_count: 0,
    };
    assert!(matches!(base.verify_reconciled(history_id, 3, 1), Err(SafeGcError::IncompleteProof(_))));
    let mut aligned = base;
    aligned.pg_projected_event_seq = 1;
    aligned.verify_reconciled(history_id, 3, 1).unwrap();
}

fn one_commit_state_machine(repo_id: Uuid, tenant_id: Uuid, history_id: Uuid, main_oid: &str) -> RefCasStateMachine {
    let mut sm = RefCasStateMachine::new();
    sm.apply(
        AppliedLogId { term: 1, index: 1 },
        RefCasCommand::InitializeGate(InitializeGateCommand {
            gate: WireGateInit {
                repository_id: repo_id,
                tenant_id,
                object_format: GitObjectFormat::Sha1,
                history_incarnation: history_id,
                authority_epoch: 1,
                group_epoch: 1,
                head_ref: "refs/heads/main".into(),
            },
            lane: RepositoryLane::LegacyUnservedGitfs,
            pack_mode: SmPackMode::MetadataOnly,
            authz_floor: 0,
        }),
    )
    .unwrap();
    let request = CommitRefsRequest::new(
        repo_id,
        tenant_id,
        Uuid::new_v4(),
        IssuerLane::new("push").unwrap(),
        1,
        Uuid::new_v4(),
        GitObjectFormat::Sha1,
        history_id,
        1,
        1,
        1,
        HeadUpdate::Keep,
        CommitMode::Atomic,
        vec![RefUpdate::new(
            RefName::new("refs/heads/main").unwrap(),
            RefPrecondition::Absent,
            RefTarget::Oid(GitOid::parse(GitObjectFormat::Sha1, main_oid).unwrap()),
        )],
    )
    .unwrap();
    let wire = WireCommitRefsRequest::from(&request);
    sm.apply(
        AppliedLogId { term: 1, index: 2 },
        RefCasCommand::BeginOperation(BeginOperationCommand { identity: wire.identity.clone(), logical_tick: 1 }),
    )
    .unwrap();
    sm.apply(
        AppliedLogId { term: 1, index: 3 },
        RefCasCommand::CommitRefs(CommitRefsCommand {
            request: wire,
            decision_id: None,
            required_holds: Vec::new(),
            policy_rejects: BTreeMap::new(),
            logical_tick: 2,
        }),
    )
    .unwrap();
    sm
}

#[test]
fn persisted_refcas_cutpoint_round_trips_and_corruption_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let (tenant_id, repo_id, history_id) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let main_oid = oid(SafeGcObjectFormat::Sha1, 7);
    let sm = one_commit_state_machine(repo_id, tenant_id, history_id, &main_oid);
    let path = persist_refcas_cutpoint_snapshot(dir.path(), repo_id, 0, &sm, &[]).unwrap();

    let source = FsSealedRefCasCutpointSource::new(dir.path());
    let (group_id, restored) = source.capture_state_machine(repo_id).unwrap().expect("sealed Ref-CAS cutpoint");
    assert_eq!(group_id, 0);
    assert_eq!(restored.snapshot().unwrap().body.next_event_seq, 1);

    std::fs::write(&path, b"{\"group_id\":0,\"snapshot\":{\"body\":{}}").unwrap();
    assert!(matches!(source.capture_state_machine(repo_id), Err(SafeGcError::IncompleteProof(_))));
}

#[test]
fn production_commit_publisher_seals_and_reloads_refcas_cutpoint() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(RefCasCommitCutpointPublisher::new(dir.path(), 0).unwrap().group_id(), 0);
    let (tenant_id, repo_id, history_id) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let main_oid = oid(SafeGcObjectFormat::Sha1, 7);
    let next_oid = oid(SafeGcObjectFormat::Sha1, 8);
    let sm = one_commit_state_machine(repo_id, tenant_id, history_id, &main_oid);
    let backend = crate::pulls::remote_merge_finalizer::InProcessRefCasBackend::new(sm)
        .with_safe_gc_cutpoint_publisher(dir.path(), 0)
        .unwrap();
    let rev = backend.state_machine().read_gate_version(repo_id).unwrap().unwrap().revision();
    let request = CommitRefsRequest::new(
        repo_id,
        tenant_id,
        Uuid::new_v4(),
        IssuerLane::new("push").unwrap(),
        2,
        Uuid::new_v4(),
        GitObjectFormat::Sha1,
        history_id,
        1,
        1,
        rev,
        HeadUpdate::Keep,
        CommitMode::Atomic,
        vec![RefUpdate::new(
            RefName::new("refs/heads/main").unwrap(),
            RefPrecondition::Present(GitOid::parse(GitObjectFormat::Sha1, &main_oid).unwrap()),
            RefTarget::Oid(GitOid::parse(GitObjectFormat::Sha1, &next_oid).unwrap()),
        )],
    )
    .unwrap();
    let resp = backend
        .apply_repo_command(
            repo_id,
            RefCasCommand::CommitRefs(CommitRefsCommand {
                request: WireCommitRefsRequest::from(&request),
                decision_id: None,
                required_holds: Vec::new(),
                policy_rejects: BTreeMap::new(),
                logical_tick: 2,
            }),
        )
        .unwrap();
    assert!(matches!(resp, ApplyResponse::RefsCommitted(_)));
    assert!(safe_gc_refcas_cutpoint_path(dir.path(), repo_id).is_file());

    let source = FsSealedRefCasCutpointSource::new(dir.path());
    let (group_id, restored) = source.capture_state_machine(repo_id).unwrap().expect("published production cutpoint");
    assert_eq!(group_id, 0);
    assert_eq!(restored.last_applied().unwrap().index, 4);
    assert_eq!(restored.read_refs(repo_id).get("refs/heads/main"), Some(&next_oid));
}

#[test]
fn cold_reopen_clears_unheld_pg_barrier_and_requires_live_rebind() {
    let (snap, _, _) = seed_fixture(SafeGcObjectFormat::Sha1, true);
    let auth = snap.authority.clone();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("journal.json");
    let authority = DurableSafeGcAuthority::open_with_journal(&path, Some(snap)).unwrap();
    let arm = distributed_arm(&auth);
    authority.set_gc_mode(GcMode::ArmedDestructive(arm.clone())).unwrap();
    authority.rebind_pending_delete_live_pg_fence(7, arm.clone()).unwrap();
    let proof = authority.build_authoritative_deletion_proof(arm.clone(), &[]).unwrap();
    let batch_id = Uuid::new_v4();
    let batch = authority
        .begin_delete_batch(batch_id, auth.incarnation_id, auth.incarnation_epoch, auth.lease_epoch, proof)
        .unwrap();
    assert_eq!(batch.proof.reader_quiescence.pg_exclusive_reader_barrier_epoch, Some(7));
    let key = batch.pending_keys[0].clone();
    drop(authority);

    let reopened = DurableSafeGcAuthority::open_with_journal(&path, None).unwrap();
    assert!(reopened.snapshot().reader_leases.pg_exclusive_barrier_epoch.is_none());
    assert!(matches!(
        reopened.mint_fenced_step_ticket(batch_id, auth.incarnation_id, auth.incarnation_epoch, auth.lease_epoch, &key),
        Err(SafeGcError::StaleDeleterFenced(_))
    ));
    reopened.rebind_pending_delete_live_pg_fence(8, distributed_arm(&auth)).unwrap();
    assert_eq!(reopened.snapshot().reader_leases.pg_exclusive_barrier_epoch, Some(8));
    assert!(
        reopened
            .mint_fenced_step_ticket(batch_id, auth.incarnation_id, auth.incarnation_epoch, auth.lease_epoch, &key)
            .unwrap()
            .is_some()
    );
}

fn distributed_arm(auth: &AuthorityRecord) -> SafeGcArmReceipt {
    SafeGcArmReceipt::seal(
        auth.tenant_id,
        auth.repo_id,
        auth.history_id,
        auth.incarnation_id,
        auth.incarnation_epoch,
        true,
        AuthorityLane::DistributedRefCas {
            ref_cas_authority_id: auth.repo_id,
            quorum_epoch: 1,
            raft_commit_index: 10,
            quorum_verified: true,
            global_hold_bridge_verified: true,
            global_hold_bridge_seq: 10,
            remote_backup_root_verified: true,
            remote_backup_root_epoch: 1,
            async_projection_only: false,
        },
    )
    .unwrap()
}
