//! Unit regressions for separated `QuorumCommitReceipt` vs `LocalWalApplyReceipt`
//! and durable peer-group Raft cutpoint proofs (`#153`).

use std::collections::{BTreeMap, BTreeSet};

use uuid::Uuid;

use crate::ref_store::GitObjectFormat;
use crate::ref_store::contract::RequestDigest;
use crate::ref_store::core::state_machine::{CloseAuthScopeCommand, RefCasCommand, ScopeLifecycle};

use super::freeze_drain::{RepoBackupRegistrationSpec, TriPartyBackupCoordinator};
use super::peer_groups::{
    ExpectedGroupCursorCut, PeerGroupBackupInput, extract_peer_expected_cuts, restore_peer_groups_state,
    verify_all_group_cursors, verify_archived_peer_groups,
};
use super::quorum_wal::DurableRaftBackend;
use super::types::{
    NewIncarnationAuthority, PairedBackupError, PgCutpointProof, PgProjectionCursorCut, PgRepositoryRowProof,
    sha256_json_tagged,
};
use super::unit_tests::seed_wal_raft;

#[test]
fn minority_local_wal_tail_is_never_replayed_and_remote_quorum_with_lagging_local_fails_closed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (repo, tenant, issuer, history, auth_id) =
        (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let wal_path = dir.path().join("quorum-split.wal");
    let (mut raft, _commit_hex, pair) = seed_wal_raft(&wal_path, 1, repo, tenant, issuer, history, 3);
    let initial_committed = raft.committed_quorum_index().expect("committed");
    assert_eq!(initial_committed, 2);

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
        expected_packs: vec![pair],
    }];
    let mut coord = TriPartyBackupCoordinator::new(10, 4);

    // (a) 1/3 minority local WAL sync (peers 1 & 2 offline):
    // Local voter 0 writes the WAL tail entry, QuorumCommitReceipt fails closed,
    // quorum_commit_index stays at 2, and reopen NEVER applies the uncommitted tail!
    raft.set_quorum_healthy(false);
    assert!(matches!(
        coord.freeze_drain_and_register(&mut raft, &specs, 12, true).unwrap_err(),
        PairedBackupError::FreezeNotHeld(_)
    ));
    assert_eq!(raft.uncommitted_local_wal_entries().expect("tail count"), 1);
    assert_eq!(raft.committed_quorum_index().expect("committed unchanged"), initial_committed);
    let (reopened_snap, _) = raft.durable_state().expect("reopen skips uncommitted tail");
    assert_eq!(reopened_snap.body.last_applied.expect("last_applied").index, initial_committed);
    assert!(reopened_snap.body.pins.is_empty());
    assert!(!coord.status().app_paused && coord.active_barrier().is_none());

    // Restore 3/3 quorum: uncommitted tail is truncated and clean 2/3+3/3 quorum succeeds
    // UNLESS local apply is disabled (`2/3` remote quorum committed, local apply lagging)!
    raft.set_quorum_healthy(true);
    raft.set_local_apply_enabled(false);
    assert!(matches!(
        coord.freeze_drain_and_register(&mut raft, &specs, 12, true).unwrap_err(),
        PairedBackupError::FreezeNotHeld(_)
    ));
    assert!(!coord.status().app_paused && coord.active_barrier().is_none());

    // (b) 2/3 remote quorum committed on peers 1 & 2 while local voter 0 WAL lags behind!
    let dir2 = tempfile::tempdir().expect("tempdir 2");
    let (mut raft2, _, pair2) =
        seed_wal_raft(&dir2.path().join("remote-quorum-lag.wal"), 1, repo, tenant, issuer, history, 3);
    let specs2 = vec![RepoBackupRegistrationSpec { expected_packs: vec![pair2], ..specs[0].clone() }];
    raft2.set_wal_sync_enabled(false);
    assert!(matches!(
        coord.freeze_drain_and_register(&mut raft2, &specs2, 12, true).unwrap_err(),
        PairedBackupError::FreezeNotHeld(_)
    ));
    assert!(matches!(raft2.durable_state().unwrap_err(), PairedBackupError::FreezeNotHeld(_)));

    // Also verify `commit_quorum_only` mints a genuine 2/3 QuorumCommitReceipt while local WAL lags.
    let dir3 = tempfile::tempdir().expect("tempdir 3");
    let (mut raft3, _, _) = seed_wal_raft(&dir3.path().join("quorum-only.wal"), 1, repo, tenant, issuer, history, 3);
    let close_cmd = RefCasCommand::CloseAuthScope(CloseAuthScopeCommand {
        scope_kind: "repo_lifecycle".into(),
        scope_id: repo,
        repository_id: Some(repo),
        tenant_id: Some(tenant),
        lifecycle: ScopeLifecycle::Closed,
        authz_floor: 15,
        change_id: Uuid::new_v4(),
        logical_tick: 20,
    });
    let qr = raft3.commit_quorum_only(&close_cmd).expect("2/3 remote quorum committed");
    qr.verify().expect("valid 2/3 QuorumCommitReceipt");
    assert_eq!(qr.voter_acks.len(), 2);
    assert_eq!(qr.voter_ids.len(), 3);
    assert!(matches!(raft3.durable_state().unwrap_err(), PairedBackupError::FreezeNotHeld(_)));
}

#[test]
fn peer_group_durable_raft_proofs_reject_epoch_incarnation_log_barrier_and_map_skew() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (repo1, tenant1, issuer1, hist1, auth1) =
        (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let (mut raft1, commit1, pair1) =
        seed_wal_raft(&dir.path().join("active-g1.wal"), 1, repo1, tenant1, issuer1, hist1, 3);
    let specs1 = vec![RepoBackupRegistrationSpec {
        repository_id: repo1,
        tenant_id: tenant1,
        owner_id: tenant1,
        object_format: GitObjectFormat::Sha256,
        history_incarnation: hist1,
        authority_epoch: 2,
        group_epoch: 3,
        authority_id: auth1,
        authority_generation: 1,
        backend_identity: RequestDigest::of("backend", &[auth1.as_bytes()]).as_hex(),
        expected_packs: vec![pair1],
    }];
    let mut coord1 = TriPartyBackupCoordinator::new(5, 2);
    let _barrier1 = coord1.freeze_drain_and_register(&mut raft1, &specs1, 14, true).expect("freeze g1");
    let (snap1, _) = raft1.durable_state().expect("g1 state");
    let active_cut = ExpectedGroupCursorCut::from_verified_snapshot(1, &snap1).expect("active cut");

    let (repo2, tenant2, issuer2, hist2) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let (mut raft2, _commit2, _) = seed_wal_raft(&dir.path().join("peer-g2.wal"), 2, repo2, tenant2, issuer2, hist2, 7);
    let mut coord2 = TriPartyBackupCoordinator::new(5, 2);
    let barrier2 =
        coord2.freeze_peer_group_and_close(&mut raft2, &[(repo2, tenant2, auth1)], 16).expect("freeze peer g2");

    let peer_inputs = [PeerGroupBackupInput { group_id: 2, freeze_barrier: &barrier2, raft: &raft2 }];
    let (peer_cuts, peer_proofs) = extract_peer_expected_cuts(1, &peer_inputs).expect("peer cuts");
    assert_eq!(peer_cuts.len(), 1);
    assert_eq!(peer_cuts[0].group_epoch, 7);

    let refs1 = BTreeMap::from([("refs/heads/main".to_owned(), commit1)]);
    let pg = PgCutpointProof {
        schema_head_version: 149,
        wal_lsn: "0/300010".into(),
        snapshot_tx: "300:300:".into(),
        postgres_major_version: "17.4".into(),
        source_cluster_incarnation: Uuid::new_v4(),
        source_storage_authority_id: auth1,
        source_storage_generation: 1,
        remote_delete_fenced: true,
        max_decision_scope_version: 16,
        pending_decisions_count: 0,
        pending_outbox_count: 0,
        projection_cursors: vec![
            PgProjectionCursorCut {
                group_id: 1,
                history_incarnation: active_cut.history_incarnation,
                group_epoch: active_cut.group_epoch,
                applied_event_seq: active_cut.applied_event_seq as i64,
                applied_log_index: active_cut.applied_index as i64,
                applied_log_term: active_cut.applied_term as i64,
                last_event_id: None,
                stream_state: "active".into(),
            },
            PgProjectionCursorCut {
                group_id: 2,
                history_incarnation: peer_cuts[0].history_incarnation,
                group_epoch: peer_cuts[0].group_epoch,
                applied_event_seq: peer_cuts[0].applied_event_seq as i64,
                applied_log_index: peer_cuts[0].applied_index as i64,
                applied_log_term: peer_cuts[0].applied_term as i64,
                last_event_id: None,
                stream_state: "active".into(),
            },
        ],
        repositories: vec![PgRepositoryRowProof {
            repository_id: repo1,
            tenant_id: tenant1,
            name: "g1-repo".into(),
            object_format: GitObjectFormat::Sha256,
            storage_backend: "pg_refstore".into(),
            history_incarnation: hist1,
            authority_epoch: 2,
            group_epoch: 3,
            gate_revision: 2,
            refs_digest: sha256_json_tagged(b"rootyard-pg-refs-v1", &refs1).expect("digest"),
            refs: refs1,
        }],
        cutpoint_digest: String::new(),
    }
    .seal()
    .expect("seal pg");

    verify_all_group_cursors(&pg, &active_cut, &peer_cuts).expect("exact multi-group match");

    // 1. PG peer cursor group_epoch, history_incarnation, or applied_log_index skew -> CutpointSkew!
    for mutate in [
        |c: &mut PgProjectionCursorCut| c.group_epoch += 1,
        |c: &mut PgProjectionCursorCut| c.history_incarnation = Uuid::new_v4(),
        |c: &mut PgProjectionCursorCut| c.applied_log_index -= 1,
    ] {
        let mut bad_pg = pg.clone();
        mutate(&mut bad_pg.projection_cursors[1]);
        bad_pg = bad_pg.seal().expect("seal bad pg");
        assert!(matches!(
            verify_all_group_cursors(&bad_pg, &active_cut, &peer_cuts).unwrap_err(),
            PairedBackupError::CutpointSkew(_)
        ));
    }

    // 2. Tampered `group_epochs` map vs `peer_groups` durable snapshots -> CutpointSkew!
    let good_map = BTreeMap::from([(1, 3), (2, 7)]);
    verify_archived_peer_groups(1, 3, &good_map, &peer_proofs).expect("archived peer valid");
    let bad_map = BTreeMap::from([(1, 3), (2, 8)]);
    assert!(matches!(
        verify_archived_peer_groups(1, 3, &bad_map, &peer_proofs).unwrap_err(),
        PairedBackupError::CutpointSkew(_)
    ));

    // 3. Missing peer durable close barrier -> FreezeNotHeld!
    let mut no_close = peer_proofs.clone();
    no_close[0].freeze_barrier.close_receipts.clear();
    assert!(matches!(
        verify_archived_peer_groups(1, 3, &good_map, &no_close).unwrap_err(),
        PairedBackupError::FreezeNotHeld(_)
    ));

    // 4. Clean-room restore of peer group produces real non-zero durable cursor state!
    let inc = NewIncarnationAuthority {
        new_cluster_incarnation: Uuid::new_v4(),
        new_storage_authority_id: Uuid::new_v4(),
        new_storage_generation: 2,
        new_history_incarnation: Uuid::new_v4(),
        new_authority_epoch: 3,
        new_group_epoch: 8,
        new_authz_floor: 26,
        new_deleter_epoch: 7,
        fenced_prior_incarnations: BTreeSet::from([hist1, hist2]),
        fenced_pre_backup_decision_ids: BTreeSet::new(),
    };
    let restored = restore_peer_groups_state(&dir.path().join("rw"), &peer_proofs, &inc).expect("restore peers");
    let p2_snap = restored.get(&2).expect("restored group 2");
    assert_eq!(p2_snap.body.gates[0].history_incarnation, inc.new_history_incarnation);
    assert_eq!(p2_snap.body.gates[0].group_epoch, 8);
    assert_eq!(p2_snap.body.last_applied.expect("applied").index, 2);
}
