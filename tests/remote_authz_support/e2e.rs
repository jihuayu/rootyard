//! Real PostgreSQL 17 + 3-node mTLS `raft-node` E2E test bodies (`#152`).

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::Result;
use serde_json::json;
use uuid::Uuid;
use zeroize::Zeroizing;

use rootyard::ref_store::core::state_machine::{
    ApplyResponse, CloseAuthScopeCommand, CommitRefsCommand, RefCasCommand, ScopeLifecycle, StateMachineError,
    WireCommitRefsRequest,
};
use rootyard::ref_store::projector::{
    PgGrantMintRequest, RemoteAuthzGrantError, RevocationDrainStatus, await_drain_before_revocation_ack,
    build_cancel_command_from_pg, build_scoped_commit_from_grant, evaluate_revocation_drain_barrier,
    load_closing_scopes_from_pg, load_decision_cancellations_from_pg, mint_signed_decision_grant_from_pg,
    plan_close_scope_commands, verify_signed_decision_grant,
};

use super::cluster::LiveRaftCluster;
use super::fixtures::{
    acquire_holds_cmd, build_commit_request, build_grant_payload, gate_base_digest_hex, hex_digest, init_gate_cmd,
    make_service_identity, make_test_keyring, make_test_realm,
};
use super::pg::{SeedPgDecision, TestPgEnv};

pub async fn run_open_to_closing_grant_rotation_crash_restart() -> Result<()> {
    let pg = TestPgEnv::setup().await?;
    let mut raft = LiveRaftCluster::start_three().await?;
    let actor = Uuid::new_v4();
    let realm = make_test_realm(pg.repo_id, pg.tenant_id);
    let mut keyring = make_test_keyring(1);
    let scope_id = Uuid::new_v4();
    let svc = make_service_identity(actor, "raft-bridge-e2e");
    let gate_digest = gate_base_digest_hex(pg.repo_id, &realm);

    raft.commit_sm_cmd(&init_gate_cmd(pg.repo_id, &realm, 1)).await?.2.map_err(|e| anyhow::anyhow!("{e:?}"))?;
    pg.seed_scope("token", scope_id, 1, "OPEN", None).await?;

    // Uncommitted PG INSERT inside caller Transaction + ROLLBACK MUST NEVER mint a valid grant.
    let op_uncommitted = Uuid::new_v4();
    let dec_uncommitted = Uuid::new_v4();
    let req_uncommitted = build_commit_request(&realm, actor, "tx-lane", 1, op_uncommitted, "refs/heads/tx", 0x70);
    let mut tx_conn = pg.pool.get().await?;
    let tx = tx_conn.transaction().await?;
    pg.seed_decision_on(
        &tx,
        &SeedPgDecision {
            decision_id: dec_uncommitted,
            actor_id: actor,
            operation_id: op_uncommitted,
            issuer_id: actor,
            lane: "tx-lane",
            sequence: 1,
            history_incarnation: realm.history_incarnation,
            authority_epoch: realm.authority_epoch,
            group_epoch: realm.group_epoch,
            base_revision: 1,
            base_gate_digest: &gate_digest,
            command_digest: &req_uncommitted.digest().as_hex(),
            ref_name: "refs/heads/tx",
            new_oid_hex: &hex_digest(0x70),
            scope_kind: "token",
            scope_id,
            observed_version: 1,
            observed_digest: &hex_digest(0xaa),
            state: "OPEN",
        },
    )
    .await?;
    let tx_mint_req = PgGrantMintRequest {
        decision_id: dec_uncommitted,
        expected_realm: realm.clone(),
        authz_epoch: 2,
        service_identity: svc.clone(),
        required_holds: vec![],
        not_after_tick: 1000,
    };
    assert_eq!(
        mint_signed_decision_grant_from_pg(&pg.pool, &keyring, &tx_mint_req).await,
        Err(RemoteAuthzGrantError::DecisionNotCommittedInPg(dec_uncommitted))
    );
    tx.rollback().await?;
    assert_eq!(
        mint_signed_decision_grant_from_pg(&pg.pool, &keyring, &tx_mint_req).await,
        Err(RemoteAuthzGrantError::DecisionNotCommittedInPg(dec_uncommitted))
    );
    drop(tx_conn);

    let op1 = Uuid::new_v4();
    let dec1 = Uuid::new_v4();
    assert_eq!(
        mint_signed_decision_grant_from_pg(
            &pg.pool,
            &keyring,
            &PgGrantMintRequest {
                decision_id: dec1,
                expected_realm: realm.clone(),
                authz_epoch: 2,
                service_identity: svc.clone(),
                required_holds: vec![],
                not_after_tick: 1000,
            },
        )
        .await,
        Err(RemoteAuthzGrantError::DecisionNotCommittedInPg(dec1))
    );

    let req1 = build_commit_request(&realm, actor, "main", 1, op1, "refs/heads/main", 0x7a);
    pg.seed_decision(&SeedPgDecision {
        decision_id: dec1,
        actor_id: actor,
        operation_id: op1,
        issuer_id: actor,
        lane: "main",
        sequence: 1,
        history_incarnation: realm.history_incarnation,
        authority_epoch: realm.authority_epoch,
        group_epoch: realm.group_epoch,
        base_revision: 1,
        base_gate_digest: &gate_digest,
        command_digest: &req1.digest().as_hex(),
        ref_name: "refs/heads/main",
        new_oid_hex: &hex_digest(0x7a),
        scope_kind: "token",
        scope_id,
        observed_version: 1,
        observed_digest: &hex_digest(0xaa),
        state: "OPEN",
    })
    .await?;

    let mint_req = PgGrantMintRequest {
        decision_id: dec1,
        expected_realm: realm.clone(),
        authz_epoch: 2,
        service_identity: svc.clone(),
        required_holds: vec![],
        not_after_tick: 1000,
    };
    let grant1 = mint_signed_decision_grant_from_pg(&pg.pool, &keyring, &mint_req).await?;
    keyring.rotate_key(2, Zeroizing::new([0x88u8; 32]), true)?;
    let grant2 = mint_signed_decision_grant_from_pg(&pg.pool, &keyring, &mint_req).await?;
    assert!(verify_signed_decision_grant(&keyring, &grant1, &realm, &svc.san_identity, 10).is_err());

    let install1 = verify_signed_decision_grant(&keyring, &grant2, &realm, &svc.san_identity, 10)?;
    let (_, _, apply1) = raft.commit_sm_cmd(&RefCasCommand::InstallScopedDecision(install1.clone())).await?;
    assert_eq!(apply1, Ok(ApplyResponse::DecisionInstalled { decision_id: dec1, replayed: false }));

    let change_id = Uuid::new_v4();
    pg.transition_scope_closing("token", scope_id, 5, change_id).await?;
    let closing = load_closing_scopes_from_pg(&pg.pool).await?;
    let close_cmds = plan_close_scope_commands(&closing, Some(pg.repo_id), Some(pg.tenant_id), 5, 20)?;
    assert_eq!(close_cmds.len(), 1);
    let (_, _, close_apply) = raft.commit_sm_cmd(&RefCasCommand::CloseAuthScope(close_cmds[0].clone())).await?;
    assert!(matches!(close_apply, Ok(ApplyResponse::AuthScopeClosed { authz_floor: 5, .. })));

    let lid = raft.wait_leader(None).await?;
    raft.nodes[&lid].rpc(json!("TriggerSnapshot")).await?;
    raft.kill_and_restart_node(lid).await?;
    let new_lid = raft.wait_leader(None).await?;
    let (sm_after, _) = raft.replay_linearizable_on(new_lid).await?;
    assert_eq!(sm_after.read_scope_floor("token", scope_id).unwrap().authz_floor, 5);
    assert_eq!(
        raft.commit_sm_cmd(&RefCasCommand::InstallScopedDecision(install1)).await?.2,
        Ok(ApplyResponse::DecisionInstalled { decision_id: dec1, replayed: true })
    );

    assert!(matches!(
        raft.commit_sm_cmd(&RefCasCommand::CloseAuthScope(CloseAuthScopeCommand {
            scope_kind: "token".into(),
            scope_id,
            repository_id: Some(pg.repo_id),
            tenant_id: Some(pg.tenant_id),
            lifecycle: ScopeLifecycle::Closed,
            authz_floor: 3,
            change_id: Uuid::new_v4(),
            logical_tick: 25,
        }))
        .await?
        .2,
        Err(StateMachineError::AuthzFloorRegression { .. })
    ));
    let op_late = Uuid::new_v4();
    let dec_late = Uuid::new_v4();
    let req_late = build_commit_request(&realm, actor, "main", 2, op_late, "refs/heads/late", 0x7b);
    let mut late_payload = build_grant_payload(&realm, dec_late, &req_late, "token", scope_id, 9, 1000);
    late_payload.service_mtls_identity = svc.san_identity.clone();
    let late_grant = keyring.sign(late_payload)?;
    let late_cmd = verify_signed_decision_grant(&keyring, &late_grant, &realm, &svc.san_identity, 26)?;
    assert!(matches!(
        raft.commit_sm_cmd(&RefCasCommand::InstallScopedDecision(late_cmd)).await?.2,
        Err(StateMachineError::ScopeClosingOrClosed { .. })
    ));
    assert!(matches!(
        mint_signed_decision_grant_from_pg(&pg.pool, &keyring, &mint_req).await,
        Err(RemoteAuthzGrantError::ScopeClosingOrMissingInPg { .. })
    ));

    raft.shutdown_all().await;
    pg.teardown().await;
    Ok(())
}

pub async fn run_cancel_commit_partition_drain_barrier() -> Result<()> {
    let pg = TestPgEnv::setup().await?;
    let mut raft = LiveRaftCluster::start_three().await?;
    let actor = Uuid::new_v4();
    let realm = make_test_realm(pg.repo_id, pg.tenant_id);
    let keyring = make_test_keyring(2);
    let scope_id = Uuid::new_v4();
    let svc = make_service_identity(actor, "raft-bridge-drain");
    let gate_digest = gate_base_digest_hex(pg.repo_id, &realm);

    pg.skew_clock_and_timezone("Pacific/Auckland", 18).await?;
    pg.seed_scope("branch_rules", scope_id, 1, "OPEN", None).await?;
    raft.commit_sm_cmd(&init_gate_cmd(pg.repo_id, &realm, 1)).await?.2.map_err(|e| anyhow::anyhow!("{e:?}"))?;

    let op_commit = Uuid::new_v4();
    let dec_commit = Uuid::new_v4();
    let hold_a = Uuid::new_v4();
    let hold_b = Uuid::new_v4();
    let required_commit_holds = vec![hold_a, hold_b];
    raft.commit_sm_cmd(&acquire_holds_cmd(&realm, actor, op_commit, &required_commit_holds))
        .await?
        .2
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;

    let req_commit = build_commit_request(&realm, actor, "main", 1, op_commit, "refs/heads/done", 0x91);
    let op_cancel = Uuid::new_v4();
    let dec_cancel = Uuid::new_v4();
    let req_cancel = build_commit_request(&realm, actor, "lane-b", 1, op_cancel, "refs/heads/wip", 0x92);
    let mut commit_grant_opt = None;
    for (dec_id, op_id, lane, req, ref_name, oid_b, holds) in [
        (dec_commit, op_commit, "main", &req_commit, "refs/heads/done", 0x91u8, required_commit_holds.clone()),
        (dec_cancel, op_cancel, "lane-b", &req_cancel, "refs/heads/wip", 0x92u8, vec![]),
    ] {
        pg.seed_decision(&SeedPgDecision {
            decision_id: dec_id,
            actor_id: actor,
            operation_id: op_id,
            issuer_id: actor,
            lane,
            sequence: 1,
            history_incarnation: realm.history_incarnation,
            authority_epoch: realm.authority_epoch,
            group_epoch: realm.group_epoch,
            base_revision: 1,
            base_gate_digest: &gate_digest,
            command_digest: &req.digest().as_hex(),
            ref_name,
            new_oid_hex: &hex_digest(oid_b),
            scope_kind: "branch_rules",
            scope_id,
            observed_version: 1,
            observed_digest: &hex_digest(0xaa),
            state: "OPEN",
        })
        .await?;
        let grant = mint_signed_decision_grant_from_pg(
            &pg.pool,
            &keyring,
            &PgGrantMintRequest {
                decision_id: dec_id,
                expected_realm: realm.clone(),
                authz_epoch: 3,
                service_identity: svc.clone(),
                required_holds: holds,
                not_after_tick: 1000,
            },
        )
        .await?;
        let cmd = verify_signed_decision_grant(&keyring, &grant, &realm, &svc.san_identity, 10)?;
        raft.commit_sm_cmd(&RefCasCommand::InstallScopedDecision(cmd))
            .await?
            .2
            .map_err(|e| anyhow::anyhow!("{e:?}"))?;
        if dec_id == dec_commit {
            commit_grant_opt = Some(grant);
        }
    }
    let commit_grant = commit_grant_opt.expect("signed commit grant");
    // Mismatched hold list fails closed on Raft; exact signed holds + commitments commit cleanly.
    assert!(matches!(
        raft.commit_sm_cmd(&RefCasCommand::CommitRefs(CommitRefsCommand {
            request: WireCommitRefsRequest::from(&req_commit),
            decision_id: Some(dec_commit),
            required_holds: vec![hold_a],
            policy_rejects: BTreeMap::new(),
            logical_tick: 11,
        }))
        .await?
        .2,
        Err(StateMachineError::DecisionDigestMismatch { .. })
    ));
    let scoped_commit =
        build_scoped_commit_from_grant(&commit_grant, WireCommitRefsRequest::from(&req_commit), BTreeMap::new(), 11);
    assert!(matches!(
        raft.commit_sm_cmd(&RefCasCommand::CommitScopedRefs(scoped_commit)).await?.2,
        Ok(ApplyResponse::RefsCommitted(_))
    ));

    pg.transition_scope_closing("branch_rules", scope_id, 6, Uuid::new_v4()).await?;
    pg.insert_cancellation(op_cancel, Some(dec_cancel), &req_cancel.digest().as_hex(), actor, "revoked").await?;
    pg.skew_clock_and_timezone("America/Los_Angeles", -26).await?;

    let close_cmds = plan_close_scope_commands(
        &load_closing_scopes_from_pg(&pg.pool).await?,
        Some(pg.repo_id),
        Some(pg.tenant_id),
        6,
        30,
    )?;
    let (_, close_log_idx, _) = raft.commit_sm_cmd(&RefCasCommand::CloseAuthScope(close_cmds[0].clone())).await?;
    let lid = raft.wait_leader(None).await?;

    let probe_draining = raft.probe_scope_via_read_index(lid, "branch_rules", scope_id).await.unwrap();
    assert!(
        !evaluate_revocation_drain_barrier(&probe_draining, "branch_rules", scope_id, 6, close_log_idx)?
            .can_ack_revocation()
    );

    raft.isolate_node(lid).await?;
    let unknown_status = await_drain_before_revocation_ack(
        "branch_rules",
        scope_id,
        6,
        close_log_idx,
        Duration::from_millis(1200),
        Duration::from_millis(40),
        || raft.probe_scope_via_read_index(lid, "branch_rules", scope_id),
    )
    .await?;
    assert!(matches!(unknown_status, RevocationDrainStatus::UnknownQuorumLoss { .. }));
    assert!(!unknown_status.can_ack_revocation());

    raft.heal_all().await?;
    let cancel_rows = load_decision_cancellations_from_pg(&pg.pool, pg.repo_id).await?;
    let cancel_cmd = build_cancel_command_from_pg(&cancel_rows[0], "lane-b", 1, 35)?;
    raft.commit_sm_cmd(&RefCasCommand::Cancel(cancel_cmd)).await?.2.map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let new_lid = raft.wait_leader(None).await?;
    let digest_before = raft.replay_linearizable_on(new_lid).await?.0.state_digest()?;
    let done = await_drain_before_revocation_ack(
        "branch_rules",
        scope_id,
        6,
        close_log_idx,
        Duration::from_secs(3),
        Duration::from_millis(40),
        || raft.probe_scope_via_read_index(new_lid, "branch_rules", scope_id),
    )
    .await?;
    assert!(done.can_ack_revocation());

    pg.skew_clock_and_timezone("UTC", 99).await?;
    let digest_after = raft.replay_linearizable_on(new_lid).await?.0.state_digest()?;
    assert_eq!(digest_before, digest_after);

    raft.shutdown_all().await;
    pg.teardown().await;
    Ok(())
}
