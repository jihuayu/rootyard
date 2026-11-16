//! PostgreSQL 17 + `RefCasStateMachine` end-to-end integration tests for #151:
//! reserve-before-publish, lost-ACK recovery, Cancel-before-Register, anti-ABA
//! fencing, non-refunding quotas, and multi-group cursor-reconciled retirement.

use anyhow::{Result, ensure};
use deadpool_postgres::{Manager, Pool};
use rootyard::blob_store::{BlobProfile, BlobStore};
use rootyard::db;
use rootyard::ref_store::artifact_hold::bridge_contract::{
    BridgeBinding, GroupHoldBinding, SharedHoldReference, SharedHoldRetirementStatus,
};
use rootyard::ref_store::artifact_hold::retention_bridge::{
    BridgeRootRegistrationPlan, RetentionBridgeError, apply_release_root_idempotent, apply_reserved_hold_to_sm,
    apply_retire_hold_batch_idempotent, begin_operation_for_binding, publish_pin_and_root_after_hold,
    read_sm_quota_counters, recover_global_hold_by_operation, recover_global_hold_by_request,
    reserve_global_hold_first, verify_state_machine_gate_for_binding,
};
use rootyard::ref_store::artifact_hold::retirement_reconcile::{
    GroupObservationStatus, RetirementBlockReason, observe_group_retirement_from_sm,
    reconcile_shared_hold_retirement_with_pg,
};
use rootyard::ref_store::artifact_hold::{AcquireArtifactHoldsRequest, ArtifactHoldPurpose, ArtifactSpec, HoldScope};
use rootyard::ref_store::core::command::CommitRefsRequest;
use rootyard::ref_store::core::state_machine::{
    AppliedLogId, ApplyResponse, CancelCommand, CommitRefsCommand, InitializeGateCommand, RefCasCommand,
    RefCasStateMachine, ReleaseRootCommand, RepositoryLane, RetireHoldBatchCommand, ScopeLifecycle,
    SetRepositoryLaneCommand, SmPackMode, WireCommitRefsRequest, WireGateInit,
};
use rootyard::ref_store::projector::{
    ProjectionError, ProjectionRealm, RefCasEventEnvelope, RefCasEventPage, TruncationCutoff,
    complete_cursor_resync_in_tx, replay_page_to_pg,
};
use rootyard::ref_store::{
    CommitMode, CoreGateInit, GitObjectFormat, GitOid, HeadUpdate, IssuerLane, MetadataPinPurpose, OperationIdentity,
    PgRefStore, PgRefStoreCore, RefName, RefPrecondition, RefTarget, RefUpdate, RequestDigest,
};
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Duration;
use tokio::time::Instant as TokioInstant;
use uuid::Uuid;

static BLOB_ENV: Mutex<()> = Mutex::new(());
const ENDPOINT: &str = "http://127.0.0.1:19000";
const BUCKET_PRIMARY: &str = "retention-bridge-primary";
const BUCKET_OTHER: &str = "retention-bridge-other";

fn deadline() -> TokioInstant {
    TokioInstant::now() + Duration::from_secs(20)
}

fn log(index: u64) -> AppliedLogId {
    AppliedLogId { term: 1, index }
}

fn dhex(label: &str) -> String {
    RequestDigest::of("retention-bridge-pg-test", &[label.as_bytes()]).as_hex()
}

fn store_for_bucket(bucket: &str) -> Result<BlobStore> {
    let _guard = BLOB_ENV.lock().unwrap_or_else(|poison| poison.into_inner());
    unsafe {
        std::env::set_var("ROOTYARD_BLOB_DRIVER", "opendal");
        std::env::set_var("ROOTYARD_BLOB_SERVICE", "s3");
        std::env::set_var("ROOTYARD_BLOB_ENDPOINT", ENDPOINT);
        std::env::set_var("ROOTYARD_BLOB_BUCKET", bucket);
        std::env::set_var("ROOTYARD_BLOB_REGION", "us-east-1");
        std::env::set_var("ROOTYARD_BLOB_ACCESS_KEY_ID", "fixture-access-key");
        std::env::set_var("ROOTYARD_BLOB_SECRET_ACCESS_KEY", "fixture-secret-key");
        std::env::set_var("ROOTYARD_BLOB_RETRY_MAX_TIMES", "0");
        std::env::set_var("ROOTYARD_BLOB_TIMEOUT_MS", "5000");
        std::env::set_var("ROOTYARD_BLOB_IO_TIMEOUT_MS", "5000");
        std::env::set_var("ROOTYARD_BLOB_ABORT_TIMEOUT_MS", "500");
        std::env::set_var("ROOTYARD_BLOB_MAX_OBJECT_BYTES", "1048576");
        std::env::remove_var("ROOTYARD_BLOB_SESSION_TOKEN");
        std::env::remove_var("ROOTYARD_BLOB_ROOT");
        std::env::remove_var("ROOTYARD_BLOB_DELETE");
        std::env::remove_var("ROOTYARD_BLOB_CONTAINER");
        std::env::remove_var("ROOTYARD_BLOB_ACCOUNT_NAME");
        std::env::remove_var("ROOTYARD_BLOB_ACCOUNT_KEY");
    }
    Ok(BlobStore::open(BlobProfile::from_env()?)?)
}

async fn setup_schema() -> Result<(Pool, Pool, String)> {
    let url = {
        let _guard = BLOB_ENV.lock().unwrap_or_else(|poison| poison.into_inner());
        std::env::var("ROOTYARD_TEST_DATABASE_URL")?
    };
    let admin = db::pool(&url)?;
    let schema = format!("retention_bridge_test_{}", Uuid::new_v4().simple());
    admin.get().await?.batch_execute(&format!("CREATE SCHEMA {schema}")).await?;
    let mut cfg: tokio_postgres::Config = url.parse()?;
    cfg.options(format!("-c search_path={schema} -c timezone=UTC -c statement_timeout=30000 -c lock_timeout=15000"));
    let pool = Pool::builder(Manager::new(cfg, tokio_postgres::NoTls))
        .runtime(deadpool_postgres::Runtime::Tokio1)
        .max_size(8)
        .build()?;
    db::migrate(&pool).await?;
    Ok((admin, pool, schema))
}

async fn seed_repo(pool: &Pool, tenant: Uuid, repo: Uuid, history: Uuid) -> Result<RequestDigest> {
    let client = pool.get().await?;
    client
        .execute(
            "INSERT INTO users(id,username) VALUES($1,$2) ON CONFLICT DO NOTHING",
            &[&tenant, &format!("u{}", &tenant.simple().to_string()[..12])],
        )
        .await?;
    client
        .execute(
            "INSERT INTO repositories(id,owner_id,name,state,object_format) VALUES($1,$2,$3,'provisioning','sha256')",
            &[&repo, &tenant, &format!("r{}", &repo.simple().to_string()[..12])],
        )
        .await?;
    drop(client);
    let init =
        CoreGateInit::new(repo, tenant, GitObjectFormat::Sha256, history, 1, 1, RefName::branch("refs/heads/main")?)?;
    let mut c = pool.get().await?;
    let gate = PgRefStoreCore.initialize(&mut c, &init, deadline()).await?;
    Ok(*gate.digest())
}

async fn register_pg_op(pool: &Pool, op: &OperationIdentity) -> Result<()> {
    let mut client = pool.get().await?;
    let tx = client.transaction().await?;
    let begun = PgRefStore.begin(&tx, op, deadline()).await?;
    ensure!(begun.created);
    tx.commit().await?;
    Ok(())
}

fn init_sm_for_repo(repo: Uuid, tenant: Uuid, history: Uuid) -> RefCasStateMachine {
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
        log(1),
        RefCasCommand::InitializeGate(InitializeGateCommand {
            gate: WireGateInit::from(&init),
            lane: RepositoryLane::ServingRefStore,
            pack_mode: SmPackMode::MetadataOnly,
            authz_floor: 1,
        }),
    )
    .unwrap();
    sm
}

fn test_plan(seed: u128) -> BridgeRootRegistrationPlan {
    let id = |n: u128| Uuid::from_u128(seed + n);
    BridgeRootRegistrationPlan {
        pin_request_id: id(1),
        snapshot_id: id(2),
        pin_id: id(3),
        pin_purpose: MetadataPinPurpose::Backup,
        lease_ticks: 50,
        pin_logical_tick: 10,
        pack_digests: vec![],
        pin_request_digest: dhex(&format!("pin-{seed}")),
        root_request_id: id(4),
        root_id: id(5),
        root_purpose: "backup".into(),
        business_intent_digest: dhex(&format!("bi-{seed}")),
        selector_kind: "snapshot".into(),
        selector_digest: dhex(&format!("sel-{seed}")),
        refs_digest: dhex(&format!("refs-{seed}")),
        pack_set_digest: dhex(&format!("packs-{seed}")),
        register_digest: dhex(&format!("reg-{seed}")),
        root_request_digest: dhex(&format!("root-{seed}")),
    }
}

#[tokio::test]
#[ignore = "requires live PostgreSQL via ROOTYARD_TEST_DATABASE_URL"]
async fn pg_bridge_reserve_before_publish_lost_ack_recovery_and_non_refunding_quotas() -> Result<()> {
    let (admin, pool, schema) = setup_schema().await?;
    let blob = store_for_bucket(BUCKET_PRIMARY)?;
    let other_blob = store_for_bucket(BUCKET_OTHER)?;
    let (tenant, repo, history, authority_id, issuer_id, op_id) =
        (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let gate_digest = seed_repo(&pool, tenant, repo, history).await?;
    let scope = HoldScope::new(
        repo,
        tenant,
        tenant,
        ArtifactHoldPurpose::RefPublication,
        GitObjectFormat::Sha256,
        history,
        1,
        1,
    )?;
    let op = OperationIdentity::new(
        repo,
        issuer_id,
        IssuerLane::new("push")?,
        1,
        op_id,
        RequestDigest::of("op", &[op_id.as_bytes()]),
    )?;
    register_pg_op(&pool, &op).await?;

    let binding = BridgeBinding::from_scope_and_operation(&scope, &op, authority_id, 1, 10, blob.backend_identity())?;
    let req_id = Uuid::new_v4();
    let spec = ArtifactSpec::new("pack", dhex("artifact-1"), 2048)?;
    let req = AcquireArtifactHoldsRequest::new(
        scope,
        op.clone(),
        req_id,
        blob.backend_identity().clone(),
        authority_id,
        1,
        gate_digest,
        vec![spec],
    )?;

    // Must fail recovery before PG hold commits.
    let mut client = pool.get().await?;
    ensure!(matches!(
        recover_global_hold_by_operation(&mut client, &scope, &binding, deadline()).await.unwrap_err(),
        RetentionBridgeError::MissingDurableHold { .. }
    ));

    // Reserve in PG first, then drop grant + response to simulate lost COMMIT ACK.
    let reserved = reserve_global_hold_first(&mut client, &blob, &req, &binding, deadline()).await?;
    ensure!(!reserved.reservation.replayed && reserved.grant.is_some());
    drop(reserved);

    // Recover strictly via original OperationIdentity without creating extra rows or charging quotas twice.
    let recovered = recover_global_hold_by_operation(&mut client, &scope, &binding, deadline()).await?;
    ensure!(recovered.replayed && recovered.recovered_from_unknown_commit && recovered.hold_ids().len() == 1);
    let by_req = recover_global_hold_by_request(&mut client, &scope, &binding, req_id, deadline()).await?;
    ensure!(by_req.ack == recovered.ack);

    let replayed = reserve_global_hold_first(&mut client, &blob, &req, &binding, deadline()).await?;
    ensure!(replayed.reservation.replayed && replayed.grant.is_none());

    // Wrong physical bucket must fail closed on backend identity check.
    let wrong_binding =
        BridgeBinding::from_scope_and_operation(&scope, &op, authority_id, 1, 10, other_blob.backend_identity())?;
    ensure!(matches!(
        recover_global_hold_by_operation(&mut client, &scope, &wrong_binding, deadline()).await.unwrap_err(),
        RetentionBridgeError::BackendMismatch
    ));

    let row = client
        .query_one("SELECT hold_count, declared_bytes FROM artifact_hold_repo_usage WHERE repository_id=$1", &[&repo])
        .await?;
    ensure!(row.get::<_, i64>(0) == 1 && row.get::<_, i64>(1) == 2048);

    // SM phase: publish refused before hold installed; succeeds + snapshot-replays after hold installed.
    let mut sm = init_sm_for_repo(repo, tenant, history);
    let plan = test_plan(100);
    ensure!(matches!(
        publish_pin_and_root_after_hold(&mut sm, log(2), log(3), &recovered, &binding, &plan).unwrap_err(),
        RetentionBridgeError::MissingDurableHold { .. }
    ));
    apply_reserved_hold_to_sm(&mut sm, log(2), &recovered, &binding)?;
    begin_operation_for_binding(&mut sm, log(3), &binding, 5)?;
    publish_pin_and_root_after_hold(&mut sm, log(4), log(5), &recovered, &binding, &plan)?;
    let (sm_q1, _) = read_sm_quota_counters(&sm, repo, tenant)?;

    let mut sm_restored = RefCasStateMachine::restore_bytes(&sm.snapshot_bytes()?)?;
    apply_reserved_hold_to_sm(&mut sm_restored, log(6), &recovered, &binding)?;
    publish_pin_and_root_after_hold(&mut sm_restored, log(7), log(8), &recovered, &binding, &plan)?;
    let rel = ReleaseRootCommand {
        request_id: Uuid::new_v4(),
        root_id: plan.root_id,
        repository_id: repo,
        tenant_id: tenant,
        owner_id: tenant,
        expected_register_digest: plan.register_digest,
        intent_digest: dhex("done"),
    };
    apply_release_root_idempotent(&mut sm_restored, log(9), rel)?;
    apply_retire_hold_batch_idempotent(
        &mut sm_restored,
        log(10),
        RetireHoldBatchCommand {
            request_id: Uuid::new_v4(),
            repository_id: repo,
            tenant_id: tenant,
            hold_ids: recovered.hold_ids(),
        },
    )?;
    let (sm_q2, _) = read_sm_quota_counters(&sm_restored, repo, tenant)?;
    ensure!(
        sm_q2.holds == sm_q1.holds
            && sm_q2.hold_declared_bytes == sm_q1.hold_declared_bytes
            && sm_q2.roots == sm_q1.roots
    );

    drop(client);
    drop(pool);
    admin.get().await?.batch_execute(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE")).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires live PostgreSQL via ROOTYARD_TEST_DATABASE_URL"]
async fn pg_bridge_cancel_before_register_and_anti_aba_fencing() -> Result<()> {
    let (admin, pool, schema) = setup_schema().await?;
    let blob = store_for_bucket(BUCKET_PRIMARY)?;
    let (tenant, repo, history, authority_id, issuer_id, op_id) =
        (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let gate_digest = seed_repo(&pool, tenant, repo, history).await?;
    let scope = HoldScope::new(
        repo,
        tenant,
        tenant,
        ArtifactHoldPurpose::RefPublication,
        GitObjectFormat::Sha256,
        history,
        1,
        1,
    )?;
    let op = OperationIdentity::new(
        repo,
        issuer_id,
        IssuerLane::new("push")?,
        1,
        op_id,
        RequestDigest::of("op-cancel", &[op_id.as_bytes()]),
    )?;
    register_pg_op(&pool, &op).await?;
    {
        let mut client = pool.get().await?;
        let tx = client.transaction().await?;
        PgRefStore.cancel(&tx, &op, deadline()).await?;
        tx.commit().await?;
    }
    let binding = BridgeBinding::from_scope_and_operation(&scope, &op, authority_id, 1, 10, blob.backend_identity())?;
    let req = AcquireArtifactHoldsRequest::new(
        scope,
        op,
        Uuid::new_v4(),
        blob.backend_identity().clone(),
        authority_id,
        1,
        gate_digest,
        vec![ArtifactSpec::new("pack", dhex("cancel-art"), 512)?],
    )?;
    let mut client = pool.get().await?;
    ensure!(reserve_global_hold_first(&mut client, &blob, &req, &binding, deadline()).await.is_err());

    let mut sm = init_sm_for_repo(repo, tenant, history);
    sm.apply(
        log(2),
        RefCasCommand::Cancel(CancelCommand {
            identity: binding.to_wire_operation_identity(),
            reason: Some("aborted".into()),
            logical_tick: 1,
        }),
    )?;
    ensure!(matches!(
        verify_state_machine_gate_for_binding(&sm, &binding).unwrap_err(),
        RetentionBridgeError::CancelledBeforeRegister { operation_id } if operation_id == op_id
    ));
    sm.apply(
        log(3),
        RefCasCommand::SetRepositoryLane(SetRepositoryLaneCommand {
            repository_id: repo,
            tenant_id: tenant,
            lane: RepositoryLane::ServingRefStore,
            lifecycle: ScopeLifecycle::Open,
            authz_floor: 1,
            history_incarnation: history,
            authority_epoch: 2,
            group_epoch: 1,
            pack_mode: SmPackMode::MetadataOnly,
        }),
    )?;
    let op2 = OperationIdentity::new(
        repo,
        issuer_id,
        IssuerLane::new("push")?,
        2,
        Uuid::new_v4(),
        RequestDigest::of("op2", b"2"),
    )?;
    let binding2 = BridgeBinding::from_scope_and_operation(&scope, &op2, authority_id, 1, 10, blob.backend_identity())?;
    ensure!(matches!(
        verify_state_machine_gate_for_binding(&sm, &binding2).unwrap_err(),
        RetentionBridgeError::GenerationConflict { field: "authority_epoch", expected: 2, actual: 1 }
    ));

    drop(client);
    drop(pool);
    admin.get().await?.batch_execute(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE")).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires live PostgreSQL via ROOTYARD_TEST_DATABASE_URL"]
async fn pg_multi_group_shared_hold_retirement_and_cursor_reconciler() -> Result<()> {
    let (admin, pool, schema) = setup_schema().await?;
    let blob = store_for_bucket(BUCKET_PRIMARY)?;
    let shared_sha = dhex("shared-physical-artifact");
    let backend_hex = blob.backend_identity().as_hex().to_owned();

    let (t1, r1, h1) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let (t2, r2, h2) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let (t3, r3, h3) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let (g1_dig, g2_dig, g3_dig) =
        (seed_repo(&pool, t1, r1, h1).await?, seed_repo(&pool, t2, r2, h2).await?, seed_repo(&pool, t3, r3, h3).await?);

    let reserve_repo = |seed: u128, group_id: i64, t: Uuid, r: Uuid, h: Uuid, g_dig: RequestDigest| {
        let pool = pool.clone();
        let blob = blob.clone();
        let shared_sha = shared_sha.clone();
        async move {
            let scope = HoldScope::new(r, t, t, ArtifactHoldPurpose::RefPublication, GitObjectFormat::Sha256, h, 1, 1)?;
            let op_id = Uuid::new_v4();
            let op = OperationIdentity::new(
                r,
                Uuid::new_v4(),
                IssuerLane::new("push")?,
                1,
                op_id,
                RequestDigest::of("op", &[op_id.as_bytes()]),
            )?;
            register_pg_op(&pool, &op).await?;
            let binding = BridgeBinding::from_scope_and_operation(
                &scope,
                &op,
                Uuid::new_v4(),
                1,
                group_id,
                blob.backend_identity(),
            )?;
            let req = AcquireArtifactHoldsRequest::new(
                scope,
                op,
                Uuid::new_v4(),
                blob.backend_identity().clone(),
                binding.authority_id,
                1,
                g_dig,
                vec![ArtifactSpec::new("pack", shared_sha, 4096)?],
            )?;
            let mut client = pool.get().await?;
            let reserved = reserve_global_hold_first(&mut client, &blob, &req, &binding, deadline()).await?;
            let mut sm = init_sm_for_repo(r, t, h);
            // Commit one ref so real RefCasEventEnvelope projects into ref_cas_projection_cursors.
            let commit_op = Uuid::new_v4();
            let commit_req = CommitRefsRequest::new(
                r,
                t,
                binding.issuer_id,
                IssuerLane::new("push")?,
                2,
                commit_op,
                GitObjectFormat::Sha256,
                h,
                1,
                1,
                1,
                HeadUpdate::Keep,
                CommitMode::Atomic,
                vec![RefUpdate::new(
                    RefName::branch("refs/heads/main")?,
                    RefPrecondition::Absent,
                    RefTarget::Oid(GitOid::parse(GitObjectFormat::Sha256, &dhex(&format!("oid-{seed}")))?),
                )],
            )?;
            sm.apply(
                log(2),
                RefCasCommand::CommitRefs(CommitRefsCommand {
                    request: WireCommitRefsRequest::from(&commit_req),
                    decision_id: None,
                    required_holds: vec![],
                    policy_rejects: BTreeMap::new(),
                    logical_tick: 2,
                }),
            )?;
            let realm = ProjectionRealm::new(h, group_id, 1)?;
            let events: Vec<_> = sm
                .read_events_since(0, 10)
                .into_iter()
                .map(|e| RefCasEventEnvelope::from_state_machine_event(realm, Some(t), None, None, &e).unwrap())
                .collect();
            replay_page_to_pg(
                &pool,
                &RefCasEventPage {
                    realm,
                    events,
                    earliest_available_event_seq: 1,
                    earliest_available_log_index: 1,
                    truncation_cutoff: None,
                    has_more: false,
                },
            )
            .await?;

            apply_reserved_hold_to_sm(&mut sm, log(3), &reserved.reservation, &binding)?;
            let plan = test_plan(seed);
            publish_pin_and_root_after_hold(&mut sm, log(4), log(5), &reserved.reservation, &binding, &plan)?;
            Ok::<_, anyhow::Error>((sm, reserved.reservation, plan, realm))
        }
    };

    let (mut sm1, res1, plan1, realm1) = reserve_repo(1000, 10, t1, r1, h1, g1_dig).await?;
    let (mut sm2, res2, plan2, realm2) = reserve_repo(2000, 20, t2, r2, h2, g2_dig).await?;
    let (mut sm3, res3, plan3, realm3) = reserve_repo(3000, 30, t3, r3, h3, g3_dig).await?;

    let retire_repo = |sm: &mut RefCasStateMachine,
                       r: Uuid,
                       t: Uuid,
                       hold_id: Uuid,
                       plan: &BridgeRootRegistrationPlan,
                       h: Uuid|
     -> Uuid {
        apply_release_root_idempotent(
            sm,
            log(6),
            ReleaseRootCommand {
                request_id: Uuid::new_v4(),
                root_id: plan.root_id,
                repository_id: r,
                tenant_id: t,
                owner_id: t,
                expected_register_digest: plan.register_digest.clone(),
                intent_digest: dhex("rel"),
            },
        )
        .unwrap();
        sm.apply(
            log(7),
            RefCasCommand::SetRepositoryLane(SetRepositoryLaneCommand {
                repository_id: r,
                tenant_id: t,
                lane: RepositoryLane::ServingRefStore,
                lifecycle: ScopeLifecycle::Closing,
                authz_floor: 1,
                history_incarnation: h,
                authority_epoch: 1,
                group_epoch: 1,
                pack_mode: SmPackMode::MetadataOnly,
            }),
        )
        .unwrap();
        let ret_id = Uuid::new_v4();
        apply_retire_hold_batch_idempotent(
            sm,
            log(8),
            RetireHoldBatchCommand { request_id: ret_id, repository_id: r, tenant_id: t, hold_ids: vec![hold_id] },
        )
        .unwrap();
        ret_id
    };

    let (ret1, ret2, ret3) = (
        retire_repo(&mut sm1, r1, t1, res1.hold_ids()[0], &plan1, h1),
        retire_repo(&mut sm2, r2, t2, res2.hold_ids()[0], &plan2, h2),
        retire_repo(&mut sm3, r3, t3, res3.hold_ids()[0], &plan3, h3),
    );
    let gb1 = GroupHoldBinding {
        group_id: 10,
        history_incarnation: h1,
        expected_group_epoch: 1,
        repository_id: r1,
        tenant_id: t1,
        hold_ids: res1.hold_ids(),
        retire_request_id: ret1,
    };
    let gb2 = GroupHoldBinding {
        group_id: 20,
        history_incarnation: h2,
        expected_group_epoch: 1,
        repository_id: r2,
        tenant_id: t2,
        hold_ids: res2.hold_ids(),
        retire_request_id: ret2,
    };
    let gb3 = GroupHoldBinding {
        group_id: 30,
        history_incarnation: h3,
        expected_group_epoch: 1,
        repository_id: r3,
        tenant_id: t3,
        hold_ids: res3.hold_ids(),
        retire_request_id: ret3,
    };

    let obs1 = observe_group_retirement_from_sm(&sm1, &gb1, &shared_sha, &backend_hex, 8)?;
    let obs2 = observe_group_retirement_from_sm(&sm2, &gb2, &shared_sha, &backend_hex, 8)?;
    let obs3 = observe_group_retirement_from_sm(&sm3, &gb3, &shared_sha, &backend_hex, 8)?;
    ensure!(
        obs1.status == GroupObservationStatus::Retired
            && obs2.status == GroupObservationStatus::Retired
            && obs3.status == GroupObservationStatus::Retired
    );

    // Trigger real PG truncation gap -> stream_state = resync_required -> reconcile MUST fail closed!
    let cutoff =
        TruncationCutoff { log_index: 8, event_seq: 5, log_term: 1, closure_digest: dhex("cutoff"), archive_uri: None };
    let trunc_err = replay_page_to_pg(
        &pool,
        &RefCasEventPage {
            realm: realm1,
            events: vec![],
            earliest_available_event_seq: 5,
            earliest_available_log_index: 8,
            truncation_cutoff: Some(cutoff.clone()),
            has_more: false,
        },
    )
    .await
    .unwrap_err();
    ensure!(matches!(trunc_err, ProjectionError::TruncatedBeforeCursor { .. }));

    let shared_two = SharedHoldReference {
        shared_hold_key: Uuid::new_v4(),
        artifact_digest: shared_sha.clone(),
        backend_identity: backend_hex.clone(),
        groups: vec![gb1.clone(), gb2.clone()],
    };
    let mut client = pool.get().await?;
    let lagging =
        reconcile_shared_hold_retirement_with_pg(&mut client, &shared_two, &[obs1.clone(), obs2.clone()], deadline())
            .await?;
    ensure!(lagging.status == SharedHoldRetirementStatus::Protected);
    ensure!(
        lagging.reasons.iter().any(|r| matches!(r, RetirementBlockReason::CursorResyncRequired { group_id: 10, .. }))
    );
    ensure!(lagging.reasons.iter().any(
        |r| matches!(r, RetirementBlockReason::UnreconciledCrossRepoHold { repository_id, .. } if *repository_id == r3)
    ));

    // Resync group 10 and 20, and delete repo 3 from `repositories` (simulating deleted repo row):
    // global `artifact_holds` preserves repo 3's hold -> reconciling only 10 & 20 STILL fails closed!
    for realm in [realm1, realm2, realm3] {
        let tx = client.transaction().await?;
        complete_cursor_resync_in_tx(&tx, realm, cutoff.clone(), Some("resync-ok".into())).await?;
        tx.commit().await?;
    }
    client.execute("DELETE FROM repositories WHERE id=$1", &[&r3]).await?;
    let still_protected =
        reconcile_shared_hold_retirement_with_pg(&mut client, &shared_two, &[obs1.clone(), obs2.clone()], deadline())
            .await?;
    ensure!(still_protected.status == SharedHoldRetirementStatus::Protected);
    ensure!(still_protected.reasons.iter().any(
        |r| matches!(r, RetirementBlockReason::UnreconciledCrossRepoHold { repository_id, .. } if *repository_id == r3)
    ));

    // Include ALL groups (10, 20, 30) -> safe to reclaim!
    let shared_all = SharedHoldReference {
        shared_hold_key: Uuid::new_v4(),
        artifact_digest: shared_sha,
        backend_identity: backend_hex,
        groups: vec![gb1, gb2, gb3],
    };
    let converged =
        reconcile_shared_hold_retirement_with_pg(&mut client, &shared_all, &[obs1, obs2, obs3], deadline()).await?;
    ensure!(
        converged.status == SharedHoldRetirementStatus::RetiredToSafeReclaim
            && converged.reconciled_groups == 3
            && converged.reasons.is_empty()
    );

    drop(client);
    drop(pool);
    admin.get().await?.batch_execute(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE")).await?;
    Ok(())
}
