//! Real-PostgreSQL integration tests for Ref-CAS event projection, durable cursors,
//! single-TX webhooks/jobs, revoked-actor projection, and truncation closures (#117).
//!
//! Run explicitly against PostgreSQL 17 with migration 149 applied:
//! `ROOTYARD_TEST_DATABASE_URL=... cargo test --test ref_cas_event_projection -- --ignored`

use anyhow::Result;
use deadpool_postgres::{Manager, Pool};
use rootyard::db;
use rootyard::ref_store::core::state_machine::{
    AppliedLogId, CommitRefsCommand, InitializeGateCommand, RefCasCommand, RefCasStateMachine, RepositoryLane,
    SmPackMode, WireCommitRefsRequest, WireGateInit,
};
use rootyard::ref_store::projector::{
    ProjectionCursor, ProjectionError, ProjectionJobState, ProjectionRealm, ProjectionStreamState, RefCasEventEnvelope,
    RefCasEventPage, SingleEventOutcome, TruncationCutoff, claim_next_projection_job, complete_cursor_resync_in_tx,
    compute_truncation_closure_digest, derive_operation_event_id, finish_projection_job, load_cursor,
    process_due_projection_jobs, project_event_in_tx, record_truncation_cutoff_in_tx, replay_page_to_pg,
    sync_projected_ref_cas_webhooks_bounded, verify_projected_operation_non_authorizing,
};
use rootyard::ref_store::{
    CommitMode, CommitRefsRequest, CoreGateInit, GitObjectFormat, GitOid, HeadUpdate, IssuerLane, RefName,
    RefPrecondition, RefTarget, RefUpdate,
};
use rootyard::webhooks::signing::sha256_hex;
use std::collections::BTreeMap;
use std::time::Duration;
use tokio::time::Instant;
use uuid::Uuid;

fn database_url() -> String {
    std::env::var("ROOTYARD_TEST_DATABASE_URL")
        .expect("ROOTYARD_TEST_DATABASE_URL must be set for ignored ref_cas_event_projection PG tests")
}

async fn setup() -> Result<(Pool, Pool, String, Uuid, Uuid)> {
    let url = database_url();
    let admin = db::pool(&url)?;
    let schema = format!("ref_cas_proj_test_{}", Uuid::new_v4().simple());
    admin.get().await?.batch_execute(&format!("CREATE SCHEMA {schema}")).await?;
    let mut config: tokio_postgres::Config = url.parse()?;
    config.options(format!("-c search_path={schema} -c timezone=UTC -c statement_timeout=15000 -c lock_timeout=10000"));
    let pool = Pool::builder(Manager::new(config, tokio_postgres::NoTls))
        .runtime(deadpool_postgres::Runtime::Tokio1)
        .max_size(12)
        .build()?;
    db::migrate(&pool).await?;
    let tenant = Uuid::new_v4();
    let repo = Uuid::new_v4();
    let username = format!("proj{}", &tenant.simple().to_string()[..12]);
    let client = pool.get().await?;
    client.execute("INSERT INTO users(id,username) VALUES($1,$2)", &[&tenant, &username]).await?;
    client
        .execute(
            "INSERT INTO repositories(id,owner_id,name,state,object_format) VALUES($1,$2,'proj-repo','ready','sha256')",
            &[&repo, &tenant],
        )
        .await?;
    Ok((admin, pool, schema, tenant, repo))
}

async fn teardown(admin: &Pool, schema: &str) -> Result<()> {
    admin.get().await?.batch_execute(&format!("DROP SCHEMA {schema} CASCADE")).await?;
    Ok(())
}

fn oid(byte: u8) -> GitOid {
    GitOid::Sha256([byte; 32])
}

fn build_sm_events(
    repo: Uuid,
    tenant: Uuid,
    history: Uuid,
    count: usize,
) -> Vec<(Uuid, rootyard::ref_store::core::state_machine::StateMachineEvent)> {
    let mut sm = RefCasStateMachine::new();
    let init = CoreGateInit::new(
        repo,
        tenant,
        GitObjectFormat::Sha256,
        history,
        1,
        1,
        RefName::branch("refs/heads/main").unwrap(),
    )
    .unwrap();
    sm.apply(
        AppliedLogId { term: 1, index: 1 },
        RefCasCommand::InitializeGate(InitializeGateCommand {
            gate: WireGateInit::from(&init),
            pack_mode: SmPackMode::MetadataOnly,
            lane: RepositoryLane::ServingRefStore,
            authz_floor: 1,
        }),
    )
    .unwrap();

    let lane = IssuerLane::new("pg-proj-test").unwrap();
    let issuer = Uuid::new_v4();
    let mut op_ids = Vec::with_capacity(count);
    for idx in 1..=count {
        let op_id = Uuid::new_v4();
        op_ids.push(op_id);
        let ref_name = RefName::branch(format!("refs/heads/b{idx}")).unwrap();
        let req = CommitRefsRequest::new(
            repo,
            tenant,
            issuer,
            lane.clone(),
            idx as i64,
            op_id,
            GitObjectFormat::Sha256,
            history,
            1,
            1,
            idx as i64,
            HeadUpdate::Keep,
            CommitMode::Atomic,
            vec![RefUpdate::new(ref_name, RefPrecondition::Absent, RefTarget::Oid(oid(idx as u8)))],
        )
        .unwrap();
        sm.apply(
            AppliedLogId { term: 1, index: (idx as u64) + 1 },
            RefCasCommand::CommitRefs(CommitRefsCommand {
                request: WireCommitRefsRequest::from(&req),
                decision_id: None,
                required_holds: vec![],
                policy_rejects: BTreeMap::new(),
                logical_tick: 100 + idx as u64,
            }),
        )
        .unwrap();
    }
    let raw = sm.read_events_since(0, usize::MAX);
    op_ids.into_iter().zip(raw).collect()
}

async fn insert_push_hook(pool: &Pool, tenant: Uuid, repo: Uuid) -> Result<Uuid> {
    let hook_id = Uuid::new_v4();
    let secret = "whsec_pg_projector_test";
    let digest = sha256_hex(secret.as_bytes());
    pool.get()
        .await?
        .execute(
            "INSERT INTO forge_webhooks(id,tenant_id,repository_id,url,secret,secret_sha256,events,active) \
             VALUES($1,$2,$3,'https://hooks.invalid/refcas',$4,$5,'[\"push\"]'::jsonb,true)",
            &[&hook_id, &tenant, &repo, &secret, &digest],
        )
        .await?;
    Ok(hook_id)
}

#[ignore]
#[tokio::test]
async fn pg_single_tx_rollback_vs_commit_and_idempotent_replay() -> Result<()> {
    let (admin, pool, schema, tenant, repo) = setup().await?;
    let hook_id = insert_push_hook(&pool, tenant, repo).await?;
    let history = Uuid::new_v4();
    let realm = ProjectionRealm::new(history, 7, 1)?;
    let events = build_sm_events(repo, tenant, history, 1);
    let env = RefCasEventEnvelope::from_state_machine_event(realm, Some(tenant), None, None, &events[0].1)?;

    // 1. Pre-commit rollback leaves zero effects, webhooks, jobs, or cursor advance.
    {
        let mut client = pool.get().await?;
        let tx = client.transaction().await?;
        let applied = project_event_in_tx(&tx, &env, None).await?;
        assert!(matches!(applied, SingleEventOutcome::Applied { enqueued_webhooks: 1, .. }));
        tx.rollback().await?;
    }
    let client = pool.get().await?;
    assert_eq!(load_cursor(&**client, 7, history).await?, None);
    let deliveries: i64 = client
        .query_one("SELECT count(*) FROM forge_webhook_deliveries WHERE webhook_id=$1", &[&hook_id])
        .await?
        .get(0);
    assert_eq!(deliveries, 0);

    // 2. Commit succeeds once, then duplicate replay emits zero extra side effects.
    drop(client);
    let mut c2 = pool.get().await?;
    let tx2 = c2.transaction().await?;
    let first = project_event_in_tx(&tx2, &env, None).await?;
    assert!(matches!(first, SingleEventOutcome::Applied { projected_refs: 1, enqueued_webhooks: 1, .. }));
    tx2.commit().await?;

    let tx3 = c2.transaction().await?;
    let second = project_event_in_tx(&tx3, &env, None).await?;
    assert!(matches!(second, SingleEventOutcome::DuplicateSkipped { .. }));
    tx3.commit().await?;

    let delivery_rows: i64 =
        c2.query_one("SELECT count(*) FROM forge_webhook_deliveries WHERE webhook_id=$1", &[&hook_id]).await?.get(0);
    let job_rows: i64 =
        c2.query_one("SELECT count(*) FROM ref_cas_projection_jobs WHERE repository_id=$1", &[&repo]).await?.get(0);
    assert_eq!(delivery_rows, 1);
    assert_eq!(job_rows, 2);

    teardown(&admin, &schema).await
}

#[ignore]
#[tokio::test]
async fn pg_disconnect_cursor_resume_ignores_max_sequence() -> Result<()> {
    let (admin, pool, schema, tenant, repo) = setup().await?;
    let hook_id = insert_push_hook(&pool, tenant, repo).await?;
    let history = Uuid::new_v4();
    let realm = ProjectionRealm::new(history, 9, 1)?;
    let events = build_sm_events(repo, tenant, history, 3);
    let envs: Vec<RefCasEventEnvelope> = events
        .iter()
        .map(|(_, ev)| RefCasEventEnvelope::from_state_machine_event(realm, Some(tenant), None, None, ev))
        .collect::<Result<_, _>>()?;

    let mut client = pool.get().await?;
    let tx = client.transaction().await?;
    project_event_in_tx(&tx, &envs[0], None).await?;
    tx.commit().await?;

    // Plant an unrelated synthetic higher webhook sequence row and simulate connection drop.
    client
        .execute(
            "INSERT INTO forge_webhook_deliveries \
             (id,webhook_id,tenant_id,repository_id,sequence,event_id,event_type,payload,request_headers,signature_256,state,attempts,max_attempts,next_attempt_unix) \
             VALUES ($1,$2,$3,$4,999,'foreign:synthetic','push','{}'::jsonb,'{}'::jsonb,'sha256='||repeat('a',64),'pending',0,5,0)",
            &[&Uuid::new_v4(), &hook_id, &tenant, &repo],
        )
        .await?;
    drop(client);

    // New client reconnects and resumes strictly from ref_cas_projection_cursors (applied_event_seq=1), not MAX(sequence)=999.
    let c2 = pool.get().await?;
    let resumed: ProjectionCursor = load_cursor(&**c2, 9, history).await?.expect("cursor exists");
    assert_eq!(resumed.applied_event_seq, 1);
    let gap_err = replay_page_to_pg(
        &pool,
        &RefCasEventPage {
            realm,
            events: vec![envs[2].clone()],
            earliest_available_event_seq: 1,
            earliest_available_log_index: 2,
            truncation_cutoff: None,
            has_more: false,
        },
    )
    .await
    .unwrap_err();
    assert!(matches!(gap_err, ProjectionError::SequenceGap { expected_min_event_seq: 2, got_event_seq: 3 }));

    let batch = replay_page_to_pg(
        &pool,
        &RefCasEventPage {
            realm,
            events: vec![envs[1].clone(), envs[2].clone()],
            earliest_available_event_seq: 1,
            earliest_available_log_index: 2,
            truncation_cutoff: None,
            has_more: false,
        },
    )
    .await?;
    assert_eq!(batch.applied_events, 2);
    assert_eq!(batch.cursor.applied_event_seq, 3);

    teardown(&admin, &schema).await
}

#[ignore]
#[tokio::test]
async fn pg_revoked_token_and_removed_member_project_and_refuse_new_writes() -> Result<()> {
    let (admin, pool, schema, tenant, repo) = setup().await?;
    let actor = Uuid::new_v4();
    let token = Uuid::new_v4();
    let client = pool.get().await?;
    client
        .execute(
            "INSERT INTO users(id,username) VALUES($1,$2)",
            &[&actor, &format!("mem{}", &actor.simple().to_string()[..8])],
        )
        .await?;
    client
        .execute(
            "INSERT INTO repository_collaborators(repository_id,tenant_id,user_id,role) VALUES($1,$2,$3,'write')",
            &[&repo, &tenant, &actor],
        )
        .await?;
    let token_digest = rootyard::db::digest("tok");
    client
        .execute(
            "INSERT INTO tokens(id,user_id,digest,display_name) VALUES($1,$2,$3,'temp')",
            &[&token, &actor, &token_digest],
        )
        .await?;

    let history = Uuid::new_v4();
    let realm = ProjectionRealm::new(history, 12, 1)?;
    let events = build_sm_events(repo, tenant, history, 1);
    let env =
        RefCasEventEnvelope::from_state_machine_event(realm, Some(tenant), Some(actor), Some(token), &events[0].1)?;

    // Revoke token and remove member BEFORE asynchronous Ref-CAS projection runs.
    client.execute("DELETE FROM tokens WHERE id=$1", &[&token]).await?;
    client
        .execute("DELETE FROM repository_collaborators WHERE repository_id=$1 AND user_id=$2", &[&repo, &actor])
        .await?;
    drop(client);

    let mut c2 = pool.get().await?;
    let tx = c2.transaction().await?;
    let res = project_event_in_tx(&tx, &env, None).await?;
    let SingleEventOutcome::Applied { op_event_id, .. } = res else {
        panic!("expected applied outcome");
    };
    tx.commit().await?;

    assert!(verify_projected_operation_non_authorizing(&**c2, &op_event_id).await?);
    let mut_attempt = c2
        .execute(
            "UPDATE ref_cas_projected_operations SET can_authorize_write = TRUE WHERE op_event_id = $1",
            &[&op_event_id],
        )
        .await;
    assert!(mut_attempt.is_err(), "CHECK / immutability must block writable historical projection rows");

    teardown(&admin, &schema).await
}

#[ignore]
#[tokio::test]
async fn pg_truncation_cutoff_resync_and_job_bridge() -> Result<()> {
    let (admin, pool, schema, tenant, repo) = setup().await?;
    let hook_id = insert_push_hook(&pool, tenant, repo).await?;
    let history = Uuid::new_v4();
    let realm = ProjectionRealm::new(history, 15, 1)?;
    let events = build_sm_events(repo, tenant, history, 3);
    let envs: Vec<RefCasEventEnvelope> = events
        .iter()
        .map(|(_, ev)| RefCasEventEnvelope::from_state_machine_event(realm, Some(tenant), None, None, ev))
        .collect::<Result<_, _>>()?;

    let mut client = pool.get().await?;
    let tx = client.transaction().await?;
    project_event_in_tx(&tx, &envs[0], None).await?;
    let op1_id = derive_operation_event_id(&realm, envs[0].log_index, envs[0].operation_id, repo)?;
    let cutoff = TruncationCutoff {
        log_index: envs[1].log_index,
        event_seq: envs[1].event_seq,
        log_term: envs[1].log_term,
        closure_digest: compute_truncation_closure_digest(
            &realm,
            envs[1].log_index,
            envs[1].event_seq,
            envs[1].log_term,
            Some(&op1_id),
        )?,
        archive_uri: Some("s3://archive/cut-2".into()),
    };
    record_truncation_cutoff_in_tx(&tx, realm, &cutoff).await?;
    tx.commit().await?;
    drop(client);

    // Truncated stream (earliest available = 3 while cursor is 1) transitions cursor to ResyncRequired.
    let err = replay_page_to_pg(
        &pool,
        &RefCasEventPage {
            realm,
            events: vec![envs[2].clone()],
            earliest_available_event_seq: 3,
            earliest_available_log_index: envs[2].log_index,
            truncation_cutoff: Some(cutoff.clone()),
            has_more: false,
        },
    )
    .await
    .unwrap_err();
    assert!(matches!(err, ProjectionError::TruncatedBeforeCursor { .. }));

    let c2 = pool.get().await?;
    let cur = load_cursor(&**c2, 15, history).await?.unwrap();
    assert_eq!(cur.stream_state, ProjectionStreamState::ResyncRequired);
    drop(c2);

    // Complete verified resync back to Active, advance remaining event 3, and run job & webhook bridge.
    let mut c3 = pool.get().await?;
    let tx_resync = c3.transaction().await?;
    let resynced = complete_cursor_resync_in_tx(&tx_resync, realm, cutoff, Some(op1_id)).await?;
    assert_eq!(resynced.stream_state, ProjectionStreamState::Active);
    tx_resync.commit().await?;
    drop(c3);

    let batch = replay_page_to_pg(
        &pool,
        &RefCasEventPage {
            realm,
            events: vec![envs[2].clone()],
            earliest_available_event_seq: 3,
            earliest_available_log_index: envs[2].log_index,
            truncation_cutoff: None,
            has_more: false,
        },
    )
    .await?;
    assert_eq!(batch.applied_events, 1);

    let owner = Uuid::new_v4();
    let job = claim_next_projection_job(&pool, owner, 30, 5).await?.expect("queued job claimed");
    assert!(finish_projection_job(&pool, &job, ProjectionJobState::UnknownHold, Some("pending audit")).await?);
    let processed = process_due_projection_jobs(&pool, owner, 16, 30).await?;
    assert!(processed >= 1);

    // Verify UnknownHold job is preserved and webhook backfill stays idempotent.
    let hold_count: i64 = pool
        .get()
        .await?
        .query_one(
            "SELECT count(*) FROM ref_cas_projection_jobs WHERE job_key=$1 AND state='unknown_hold'",
            &[&job.job_key],
        )
        .await?
        .get(0);
    assert_eq!(hold_count, 1);

    let extra_backfill =
        sync_projected_ref_cas_webhooks_bounded(&pool, tenant, repo, 32, Instant::now() + Duration::from_secs(5))
            .await?;
    assert_eq!(extra_backfill, 0);
    let deliveries: i64 = pool
        .get()
        .await?
        .query_one("SELECT count(*) FROM forge_webhook_deliveries WHERE webhook_id=$1", &[&hook_id])
        .await?
        .get(0);
    assert_eq!(deliveries, 2);

    teardown(&admin, &schema).await
}
