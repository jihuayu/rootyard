//! Additional deterministic Ref-CAS projector state-machine scenarios (#117).

use super::{apply_commit, init_sm, make_request, oid};
use rootyard::ref_store::projector::{
    InMemoryProjectionLedger, InMemorySmEventSource, ProjectionCursor, ProjectionError, ProjectionJobKind,
    ProjectionJobState, ProjectionRealm, ProjectionStreamState, RefCasEventEnvelope, SingleEventOutcome,
    TruncationCutoff, assert_projection_cannot_authorize_write, complete_cursor_resync,
    compute_truncation_closure_digest, plan_operation_projection,
};
use uuid::Uuid;

#[test]
fn watch_loss_reconnect_and_paged_backlog_recovery() {
    let repo = Uuid::from_u128(31);
    let tenant = Uuid::from_u128(32);
    let issuer = Uuid::from_u128(33);
    let history = Uuid::from_u128(0xDD);
    let realm = ProjectionRealm::new(history, 14, 1).unwrap();

    let mut sm = init_sm(repo, tenant, history);
    for seq in 1..=6 {
        let ref_str =
            if seq == 4 { "refs/rootyard-ci/runs/r4".to_owned() } else { format!("refs/heads/feature-{seq}") };
        apply_commit(
            &mut sm,
            1,
            (seq as u64) + 1,
            make_request(
                (repo, tenant, issuer, history),
                seq,
                Uuid::from_u128(400 + seq as u128),
                seq,
                vec![(&ref_str, None, Some(oid(seq as u8)))],
            ),
            200 + seq as u64,
        );
    }

    let source = InMemorySmEventSource::from_state_machine(&sm, realm, Some(tenant), None, None).unwrap();
    let mut ledger = InMemoryProjectionLedger::default();
    ledger.register_push_webhook(repo, tenant, Uuid::from_u128(901));

    // Apply only first event before watch stream drops.
    ledger.apply_event_with_fault(&source.events[0], None).unwrap();
    let outcome = ledger.replay_from_source(&source, realm, 2).unwrap();
    assert_eq!(outcome.applied_events, 5);
    assert_eq!(outcome.batches, 3);
    assert_eq!(outcome.cursor.applied_event_seq, 6);
    // Event #4 is reserved `refs/rootyard-ci/*`: 5 push webhooks total, plus ArtifactReconcile job!
    assert_eq!(ledger.webhook_deliveries.len(), 5);
    assert!(ledger.jobs.values().any(|j| j.kind == ProjectionJobKind::ArtifactReconcile));
}

#[test]
fn revoked_token_and_removed_member_committed_projection_and_non_auth_guard() {
    let repo = Uuid::from_u128(41);
    let tenant = Uuid::from_u128(42);
    let actor = Uuid::from_u128(43);
    let token = Uuid::from_u128(44);
    let history = Uuid::from_u128(0xEE);
    let realm = ProjectionRealm::new(history, 19, 1).unwrap();

    let mut sm = init_sm(repo, tenant, history);
    apply_commit(
        &mut sm,
        1,
        2,
        make_request(
            (repo, tenant, actor, history),
            1,
            Uuid::from_u128(501),
            1,
            vec![("refs/heads/main", None, Some(oid(9)))],
        ),
        50,
    );
    let source = InMemorySmEventSource::from_state_machine(&sm, realm, Some(tenant), Some(actor), Some(token)).unwrap();

    let mut ledger = InMemoryProjectionLedger::default();
    ledger.revoke_token_and_member(repo, actor, token);
    let applied = ledger.apply_event_with_fault(&source.events[0], None).unwrap();
    let SingleEventOutcome::Applied { op_event_id, .. } = applied else {
        panic!("expected committed historical fact to project even after actor revocation");
    };

    let op_rec = ledger.operations.get(&op_event_id).unwrap().clone();
    assert!(!op_rec.can_authorize_write);
    assert!(ledger.check_receipt_cannot_authorize_new_write(&op_event_id).is_err());

    let mut forged = op_rec;
    forged.can_authorize_write = true;
    assert!(matches!(assert_projection_cannot_authorize_write(&forged), Err(ProjectionError::AuthorityViolation(_))));
}

#[test]
fn truncation_closure_cutoff_reconcile_and_ttl_preservation() {
    let repo = Uuid::from_u128(51);
    let tenant = Uuid::from_u128(52);
    let issuer = Uuid::from_u128(53);
    let history = Uuid::from_u128(0xFF);
    let realm = ProjectionRealm::new(history, 23, 1).unwrap();

    let mut sm = init_sm(repo, tenant, history);
    for seq in 1..=4 {
        apply_commit(
            &mut sm,
            1,
            (seq as u64) + 1,
            make_request(
                (repo, tenant, issuer, history),
                seq,
                Uuid::from_u128(600 + seq as u128),
                seq,
                vec![(&format!("refs/heads/t{seq}"), None, Some(oid(seq as u8)))],
            ),
            300 + seq as u64,
        );
    }

    let mut source = InMemorySmEventSource::from_state_machine(&sm, realm, Some(tenant), None, None).unwrap();
    let mut ledger = InMemoryProjectionLedger::default();
    ledger.apply_event_with_fault(&source.events[0], None).unwrap();

    let op2_id = source.operation_event_id_at(1).unwrap();
    let digest2 = compute_truncation_closure_digest(&realm, 3, 2, 1, Some(&op2_id)).unwrap();
    let cutoff = TruncationCutoff {
        log_index: 3,
        event_seq: 2,
        log_term: 1,
        closure_digest: digest2,
        archive_uri: Some("s3://archive/g23-cut2".into()),
    };
    source.truncate_up_to(cutoff.clone()).unwrap();

    // Conflicting cutoff equivocation is rejected cleanly.
    let bad_cutoff = TruncationCutoff { closure_digest: "f".repeat(64), ..cutoff.clone() };
    ledger.record_truncation_cutoff(realm, cutoff.clone()).unwrap();
    assert!(matches!(ledger.record_truncation_cutoff(realm, bad_cutoff), Err(ProjectionError::Equivocation { .. })));

    // Replaying truncated stream behind cursor flips state to ResyncRequired instead of guessing MAX(id).
    let err = ledger.replay_from_source(&source, realm, 2).unwrap_err();
    assert!(matches!(err, ProjectionError::TruncatedBeforeCursor { .. }));
    assert_eq!(ledger.cursor_for(&realm).unwrap().stream_state, ProjectionStreamState::ResyncRequired);

    // Put one job in UnknownHold and verify TTL sweeps never discard unknown/dedup entries.
    let first_job = ledger.jobs.values_mut().next().unwrap();
    first_job.state = ProjectionJobState::UnknownHold;
    assert_eq!(ledger.sweep_with_ttl_never_drops_unknown_or_dedup(), 1);

    // Verified resync reconciles cursor cleanly back to Active and processes remaining backlog.
    let cursor = ledger.cursors.get_mut(&(23, history)).unwrap();
    complete_cursor_resync(cursor, cutoff, Some(op2_id)).unwrap();
    assert_eq!(cursor.stream_state, ProjectionStreamState::Active);

    let caught_up = ledger.replay_from_source(&source, realm, 4).unwrap();
    assert_eq!(caught_up.applied_events, 2);
    assert_eq!(caught_up.cursor.applied_event_seq, 4);
}

#[test]
fn strict_serde_deny_unknown_fields_on_projection_records() {
    let history = Uuid::from_u128(1);
    let realm_bad = serde_json::json!({
        "history_incarnation": history,
        "group_id": 1,
        "group_epoch": 1,
        "extra": true
    });
    assert!(serde_json::from_value::<ProjectionRealm>(realm_bad).is_err());

    let cursor_bad = serde_json::json!({
        "realm": { "history_incarnation": history, "group_id": 1, "group_epoch": 1 },
        "applied_event_seq": 0,
        "applied_log_index": 0,
        "applied_log_term": 0,
        "last_event_id": null,
        "truncation_cutoff": null,
        "stream_state": "active",
        "unexpected": 123
    });
    assert!(serde_json::from_value::<ProjectionCursor>(cursor_bad).is_err());

    let env_bad = serde_json::json!({
        "realm": { "history_incarnation": history, "group_id": 1, "group_epoch": 1 },
        "event_seq": 1,
        "log_index": 2,
        "log_term": 1,
        "repository_id": history,
        "tenant_id": null,
        "actor_id": null,
        "token_id": null,
        "revision": 1,
        "operation_id": history,
        "outcome": "committed",
        "payload": {},
        "bogus": "nope"
    });
    assert!(serde_json::from_value::<RefCasEventEnvelope>(env_bad).is_err());

    let plan = plan_operation_projection(&RefCasEventEnvelope {
        realm: ProjectionRealm::new(history, 1, 1).unwrap(),
        event_seq: 1,
        log_index: 2,
        log_term: 1,
        repository_id: history,
        tenant_id: None,
        actor_id: None,
        token_id: None,
        revision: 1,
        operation_id: history,
        outcome: "noop_custom".into(),
        payload: serde_json::json!({}),
    })
    .unwrap();
    assert!(!plan.operation.can_authorize_write);
}
