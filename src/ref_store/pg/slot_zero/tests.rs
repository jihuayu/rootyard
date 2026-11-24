use super::{
    ProofFacts, SlotZeroAdmissionRequest, SlotZeroPreview, insert_attempt, insert_wrapper, proof_digest,
    validate_request,
};
use crate::{
    db,
    ref_store::{
        CommitMode, CommitRejectCode, CommitRejection, CommitTerminal, GitObjectFormat, IssuerLane, OperationIdentity,
        OperationLookup, OperationState, PgRefStore, RefCommitResult, RefStoreError, RequestDigest, TerminalOutcome,
        core::{
            CoreGate, GitOid, HeadUpdate, RefName, RefPrecondition, RefUpdate,
            pack_commit::{
                MembershipDigest, PackCommitError, PackCommitExpectation, PackCommitPlan, PackCommitRejectCode,
                PackCommitScope, PackMode,
            },
        },
        pg::{
            public_attempt::{PublicAttemptLookup, PublicAttemptRequest},
            public_terminal::PublicAttemptTerminalOutcome,
        },
    },
};
use anyhow::Context;
use deadpool_postgres::{Manager, Pool, Runtime};
use std::{
    future::Future,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    sync::oneshot,
    time::{Instant, sleep, timeout},
};
use tokio_postgres::Transaction;
use uuid::Uuid;

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(15)
}

const WAIT: Duration = Duration::from_secs(10);

fn append_cleanup(mut error: anyhow::Error, label: &str, cleanup: anyhow::Result<()>) -> anyhow::Error {
    if let Err(cleanup_error) = cleanup {
        error = anyhow::anyhow!("{error:#}; {label} also failed: {cleanup_error:#}");
    }
    error
}

async fn rollback_bounded(tx: Transaction<'_>) -> anyhow::Result<()> {
    match timeout(WAIT, tx.rollback()).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(error.into()),
        Err(_) => Err(anyhow::anyhow!("transaction rollback did not finish within {WAIT:?}")),
    }
}

async fn abort_worker(worker: &mut tokio::task::JoinHandle<anyhow::Result<()>>) -> anyhow::Result<()> {
    worker.abort();
    match timeout(WAIT, &mut *worker).await {
        Ok(Ok(result)) => result,
        Ok(Err(error)) if error.is_cancelled() => Ok(()),
        Ok(Err(error)) => Err(error.into()),
        Err(_) => Err(anyhow::anyhow!("aborted worker did not join within {WAIT:?}")),
    }
}

#[derive(Clone)]
struct Fixture {
    admin: Pool,
    pool: Pool,
    database: String,
    actor: Uuid,
    repo: Uuid,
    history: Uuid,
    backend: String,
    restore: Uuid,
    gate: CoreGate,
}

struct FixtureSeed {
    pool: Pool,
    actor: Uuid,
    repo: Uuid,
    history: Uuid,
    backend: String,
    restore: Uuid,
    gate: CoreGate,
}

/// Tear down a database whose ownership is already proven by a successful
/// `CREATE DATABASE`. The caller must have dropped the fixture pool/clients
/// first. Every checkout and SQL statement is bounded; failures name the exact
/// database and leave it in place for inspection.
async fn cleanup_owned_database(admin: &Pool, database: &str) -> anyhow::Result<()> {
    let client = timeout(WAIT, admin.get())
        .await
        .with_context(|| format!("owned database {database} cleanup admin checkout did not finish"))??;
    match timeout(
        WAIT,
        client.query(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
             WHERE datname=$1 AND pid<>pg_backend_pid()",
            &[&database],
        ),
    )
    .await
    {
        Ok(Ok(_)) => {}
        Ok(Err(error)) => {
            return Err(
                anyhow::Error::new(error).context(format!("terminating backends of owned database {database} failed"))
            );
        }
        Err(_) => return Err(anyhow::anyhow!("terminating backends of owned database {database} timed out")),
    }
    match timeout(WAIT, client.batch_execute(&format!("DROP DATABASE {database}"))).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(anyhow::Error::new(error).context(format!("dropping owned database {database} failed"))),
        Err(_) => Err(anyhow::anyhow!("dropping owned database {database} timed out")),
    }
}

async fn fixture() -> anyhow::Result<Fixture> {
    fixture_with_setup_check(|_| Ok(())).await
}

/// Create one random, owned PG17 database and run the complete setup. The
/// hook runs after the full seed and is test-only: a non-empty result simulates
/// a setup failure without changing the production or fixture success path.
async fn fixture_with_setup_check<F>(check: F) -> anyhow::Result<Fixture>
where
    F: FnOnce(&str) -> anyhow::Result<()>,
{
    let base_url = std::env::var("ROOTYARD_TEST_DATABASE_URL")?;
    let admin = db::pool(&base_url)?;
    // Migration 152 resolves `public.cluster_authority` explicitly, so these
    // wrapper tests need a job-owned database whose public schema is migrated,
    // not a schema-isolated search_path. The SQL fixtures use the same shape.
    // `ROOTYARD_TEST_DATABASE_URL` therefore needs CREATEDB.
    let database = format!("slot_zero_{}", Uuid::new_v4().simple());

    // CREATE is the ownership linearization point. Record the name only after
    // it returns an acknowledged success, exactly like the existing Python
    // fixtures. If CREATE returns an error the server may or may not have
    // created the database (including a lost reply), so ownership is unproven
    // and cleanup must not touch it.
    let create = timeout(WAIT, admin.get()).await.context("fixture CREATE admin checkout did not finish")??;
    timeout(WAIT, create.batch_execute(&format!("CREATE DATABASE {database}")))
        .await
        .context("fixture CREATE DATABASE did not finish")??;
    drop(create);

    // Everything below can fail after ownership is proven. The async block owns
    // the pool and every client, so an early `?` drops them before the match
    // calls the shared cleanup helper.
    let setup: anyhow::Result<FixtureSeed> = async {
        let mut config: tokio_postgres::Config = base_url.parse()?;
        config.dbname(database.as_str());
        config.options("-c search_path=public -c timezone=UTC -c statement_timeout=15000 -c lock_timeout=10000");
        let pool =
            Pool::builder(Manager::new(config, tokio_postgres::NoTls)).runtime(Runtime::Tokio1).max_size(8).build()?;
        db::migrate(&pool).await?;

        let actor = Uuid::new_v4();
        let repo = Uuid::new_v4();
        let history = Uuid::new_v4();
        let backend = "a".repeat(64);
        let client = pool.get().await?;
        client
            .execute(
                "INSERT INTO users(id,username) VALUES($1,$2)",
                &[&actor, &format!("slotzero{}", &actor.simple().to_string()[..12])],
            )
            .await?;
        client
            .execute(
                "INSERT INTO repositories(id,owner_id,name,state,storage_backend,object_format)
                 VALUES($1,$2,'slot-zero','provisioning','pg_refstore','sha1')",
                &[&repo, &actor],
            )
            .await?;
        client
            .execute(
                "INSERT INTO ref_store_core_gates(repository_id,tenant_id,object_format,history_incarnation,
                     authority_epoch,group_epoch,head_ref,revision)
                 VALUES($1,$2,'sha1',$3,1,1,'refs/heads/main',1)",
                &[&repo, &actor, &history],
            )
            .await?;
        client
            .execute(
                "INSERT INTO ref_store_core_protocol_repos(repository_id,tenant_id,object_format,
                     history_incarnation,authority_epoch,group_epoch,decision_required)
                 VALUES($1,$2,'sha1',$3,1,1,true)",
                &[&repo, &actor, &history],
            )
            .await?;
        client
            .execute(
                "INSERT INTO ref_store_serving_repositories(repository_id,owner_id,name,object_format,
                     history_incarnation,authority_epoch,group_epoch,backend_identity,state)
                 VALUES($1,$2,'slot-zero','sha1',$3,1,1,$4,'pending')",
                &[&repo, &actor, &history, &backend],
            )
            .await?;
        client
            .execute("UPDATE ref_store_serving_repositories SET state='ready' WHERE repository_id=$1", &[&repo])
            .await?;
        client.execute("UPDATE repositories SET state='ready' WHERE id=$1", &[&repo]).await?;

        let restore: Uuid =
            client.query_one("SELECT incarnation FROM cluster_authority WHERE singleton", &[]).await?.get(0);
        let row = client
            .query_one(
                "SELECT tenant_id,object_format,history_incarnation,authority_epoch,group_epoch,head_ref,revision
                 FROM ref_store_core_gates WHERE repository_id=$1",
                &[&repo],
            )
            .await?;
        let gate = CoreGate::new(
            repo,
            row.get(0),
            GitObjectFormat::parse(&row.get::<_, String>(1))?,
            row.get(2),
            row.get(3),
            row.get(4),
            RefName::new(row.get::<_, String>(5))?,
            row.get(6),
        )?;
        check(&database)?;
        drop(client);
        Ok(FixtureSeed { pool, actor, repo, history, backend, restore, gate })
    }
    .await;

    match setup {
        Ok(seed) => Ok(Fixture {
            admin,
            pool: seed.pool,
            database,
            actor: seed.actor,
            repo: seed.repo,
            history: seed.history,
            backend: seed.backend,
            restore: seed.restore,
            gate: seed.gate,
        }),
        Err(original) => {
            let cleanup = cleanup_owned_database(&admin, &database).await;
            Err(match cleanup {
                Ok(()) => original,
                Err(cleanup_error) => append_cleanup(original, "fixture setup database cleanup", Err(cleanup_error)),
            })
        }
    }
}

async fn with_fixture<F, Fut>(body: F) -> anyhow::Result<()>
where
    F: FnOnce(Fixture) -> Fut,
    Fut: Future<Output = anyhow::Result<()>> + Send + 'static,
{
    let fixture = fixture().await?;
    let admin = fixture.admin.clone();
    let database = fixture.database.clone();
    let outcome = tokio::spawn(body(fixture)).await;
    // The spawned body owns the only fixture pool; awaiting its JoinHandle
    // guarantees it was dropped (success, error or panic) before this point.
    let cleanup = cleanup_owned_database(&admin, &database).await;
    match (outcome, cleanup) {
        (Ok(Ok(())), Ok(())) => Ok(()),
        (Ok(Err(error)), Ok(())) => Err(error),
        (Ok(Ok(())), Err(cleanup_error)) => Err(cleanup_error),
        (Ok(Err(error)), Err(cleanup_error)) => Err(append_cleanup(error, "database cleanup", Err(cleanup_error))),
        (Err(join_error), Ok(())) => Err(join_error.into()),
        (Err(join_error), Err(cleanup_error)) => {
            Err(append_cleanup(join_error.into(), "database cleanup", Err(cleanup_error)))
        }
    }
}

fn slot_zero_request(fixture: &Fixture, public_id: Uuid, private_id: Uuid) -> SlotZeroAdmissionRequest {
    SlotZeroAdmissionRequest {
        repository_id: fixture.repo,
        admission_owner_id: fixture.actor,
        issuer_id: fixture.actor,
        lane: IssuerLane::new("slot-zero").unwrap(),
        public_id,
        private_id,
        wire_digest: RequestDigest::from_bytes([1; 32]),
        request_mode: CommitMode::Atomic,
        backend_identity: fixture.backend.clone(),
        object_format: GitObjectFormat::Sha1,
        history_incarnation: fixture.history,
        authority_epoch: 1,
        group_epoch: 1,
        restore_incarnation: fixture.restore,
    }
}

fn plan_for(
    fixture: &Fixture,
    request: &SlotZeroAdmissionRequest,
    preview: SlotZeroPreview,
) -> Result<PackCommitPlan, PackCommitError> {
    let identity = OperationIdentity::new(
        request.repository_id,
        request.issuer_id,
        request.lane.clone(),
        preview.sequence(),
        request.private_id,
        RequestDigest::from_bytes([9; 32]),
    )
    .map_err(PackCommitError::from)?;
    let scope = PackCommitScope::new(
        request.repository_id,
        request.admission_owner_id,
        request.admission_owner_id,
        request.object_format,
        request.history_incarnation,
        request.authority_epoch,
        request.group_epoch,
    )
    .map_err(PackCommitError::from)?;
    let expected = PackCommitExpectation::new(preview.base_revision(), *fixture.gate.digest(), PackMode::MetadataOnly)
        .map_err(PackCommitError::from)?;
    let refs = vec![RefUpdate::new(
        RefName::new("refs/heads/main").map_err(PackCommitError::from)?,
        RefPrecondition::Absent,
        GitOid::target_value(request.object_format, &"a".repeat(request.object_format.oid_hex_len()))
            .map_err(PackCommitError::from)?,
    )];
    PackCommitPlan::new_with_mode(
        scope,
        identity,
        expected,
        HeadUpdate::Keep,
        refs,
        MembershipDigest::of(&[]),
        Vec::new(),
        Vec::new(),
        request.request_mode,
    )
}

async fn seed_wrapper_without_binding(
    tx: &Transaction<'_>,
    fixture: &Fixture,
    request: &SlotZeroAdmissionRequest,
    plan_digest: RequestDigest,
    proof: RequestDigest,
) -> anyhow::Result<()> {
    tx.query_one(
        "SELECT rootyard_ref_store_lock_public_operation($1,$2,$3)",
        &[&request.repository_id, &request.public_id, &request.private_id],
    )
    .await?;
    tx.execute(
        "INSERT INTO ref_store_issuer_lanes(repository_id,issuer_id,lane,last_reserved_sequence)
             VALUES($1,$2,$3,1) ON CONFLICT(repository_id,issuer_id,lane) DO NOTHING",
        &[&request.repository_id, &request.issuer_id, &request.lane.as_str()],
    )
    .await?;
    insert_wrapper(tx, request).await?;
    insert_attempt(tx, request, plan_digest, proof, fixture.gate.revision()).await?;
    tx.execute(
        "INSERT INTO ref_store_operations(repository_id,issuer_id,lane,sequence,operation_id,request_digest,state)
             VALUES($1,$2,$3,1,$4,$5,'pending')",
        &[
            &request.repository_id,
            &request.issuer_id,
            &request.lane.as_str(),
            &request.private_id,
            &plan_digest.as_hex(),
        ],
    )
    .await?;
    Ok(())
}

fn assert_ledger_integrity(error: &PackCommitError, detail: &str) {
    match error {
        PackCommitError::Rejected(rejection) => {
            assert_eq!(rejection.code, PackCommitRejectCode::LedgerIntegrity);
            assert_eq!(rejection.detail, detail);
        }
        other => panic!("expected ledger_integrity, got {other:?}"),
    }
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn slot_zero_admission_commits_then_exact_retry_replays() -> anyhow::Result<()> {
    with_fixture(|fixture| async move {
        let public = Uuid::new_v4();
        let private = Uuid::new_v4();
        let request = slot_zero_request(&fixture, public, private);
        let mut client = fixture.pool.get().await?;
        let tx = tokio_postgres::Client::transaction(&mut client).await?;
        let (tx, receipt) = PgRefStore
            .admit_slot_zero_in_tx(tx, &request, |preview| plan_for(&fixture, &request, preview), deadline())
            .await?
            .into_parts();
        let receipt = receipt?;
        assert!(!receipt.replayed);
        assert_eq!(receipt.sequence, 1);
        assert_eq!(receipt.private_id, private);
        assert_eq!(receipt.state, OperationState::Pending);
        tx.commit().await?;

        let row = client
            .query_one(
                "SELECT a.private_id,a.plan_digest,a.proof_digest,a.base_revision,
                            o.sequence,o.request_digest,o.state,
                            s.producer_request_digest,s.plan_parent_digest,
                            w.wire_digest,w.current_slot,w.state
                     FROM ref_store_public_operations w
                     JOIN ref_store_private_attempts a
                       ON a.repository_id=w.repository_id AND a.public_id=w.public_id AND a.slot=0
                     JOIN ref_store_operations o
                       ON o.repository_id=a.repository_id AND o.operation_id=a.private_id
                     JOIN ref_store_serving_operations s
                       ON s.repository_id=o.repository_id AND s.operation_id=o.operation_id
                     WHERE w.repository_id=$1 AND w.public_id=$2",
                &[&fixture.repo, &public],
            )
            .await?;
        assert_eq!(row.get::<_, Uuid>(0), private);
        assert_eq!(row.get::<_, String>(1), receipt.plan_digest.as_hex());
        assert_eq!(row.get::<_, String>(2), receipt.proof_digest.as_hex());
        assert_eq!(row.get::<_, i64>(3), receipt.base_revision);
        assert_eq!(row.get::<_, i64>(4), 1);
        assert_eq!(row.get::<_, String>(5), receipt.plan_digest.as_hex());
        assert_eq!(row.get::<_, String>(6), "pending");
        assert_eq!(row.get::<_, String>(7), request.wire_digest.as_hex());
        assert_eq!(row.get::<_, String>(8), receipt.plan_digest.as_hex());
        assert_eq!(row.get::<_, String>(9), request.wire_digest.as_hex());
        assert_eq!(row.get::<_, i16>(10), 0);
        assert_eq!(row.get::<_, String>(11), "pending");

        let retry = slot_zero_request(&fixture, public, Uuid::new_v4());
        let tx = tokio_postgres::Client::transaction(&mut client).await?;
        let (tx, replay) = PgRefStore
            .admit_slot_zero_in_tx(
                tx,
                &retry,
                |_| Err(PackCommitError::Invalid("an exact replay must not build a plan")),
                deadline(),
            )
            .await?
            .into_parts();
        let replay = replay?;
        assert!(replay.replayed);
        assert_eq!(replay.private_id, private);
        assert_eq!(replay.sequence, 1);
        tx.rollback().await?;

        let next_request = slot_zero_request(&fixture, Uuid::new_v4(), Uuid::new_v4());
        let tx = tokio_postgres::Client::transaction(&mut client).await?;
        let (tx, next) = PgRefStore
            .admit_slot_zero_in_tx(tx, &next_request, |preview| plan_for(&fixture, &next_request, preview), deadline())
            .await?
            .into_parts();
        let next = next?;
        assert_eq!(next.sequence, 2);
        tx.rollback().await?;
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn slot_zero_rejects_equal_ids_private_conflict_and_wire_rebinding() -> anyhow::Result<()> {
    with_fixture(|fixture| async move {
        let public = Uuid::new_v4();
        let private = Uuid::new_v4();
        let equal = slot_zero_request(&fixture, public, public);
        let mut client = fixture.pool.get().await?;
        let tx = tokio_postgres::Client::transaction(&mut client).await?;
        let (tx, error) = PgRefStore
            .admit_slot_zero_in_tx(
                tx,
                &equal,
                |_| Err(PackCommitError::Invalid("equal ids must not build a plan")),
                deadline(),
            )
            .await?
            .into_parts();
        let error = error.unwrap_err();
        assert!(matches!(error, PackCommitError::RefStore(RefStoreError::InvalidIdentity(_))));
        tx.rollback().await?;

        let request = slot_zero_request(&fixture, public, private);
        let tx = tokio_postgres::Client::transaction(&mut client).await?;
        let (tx, receipt) = PgRefStore
            .admit_slot_zero_in_tx(tx, &request, |preview| plan_for(&fixture, &request, preview), deadline())
            .await?
            .into_parts();
        let _ = receipt?;
        tx.commit().await?;

        let conflict = slot_zero_request(&fixture, Uuid::new_v4(), private);
        let tx = tokio_postgres::Client::transaction(&mut client).await?;
        let (tx, error) = PgRefStore
            .admit_slot_zero_in_tx(
                tx,
                &conflict,
                |_| Err(PackCommitError::Invalid("private conflict must not build a plan")),
                deadline(),
            )
            .await?
            .into_parts();
        let error = error.unwrap_err();
        assert!(matches!(error, PackCommitError::RefStore(RefStoreError::IdentityConflict)));
        tx.rollback().await?;

        let mut rebind = slot_zero_request(&fixture, public, Uuid::new_v4());
        rebind.wire_digest = RequestDigest::from_bytes([2; 32]);
        let tx = tokio_postgres::Client::transaction(&mut client).await?;
        let (tx, error) = PgRefStore
            .admit_slot_zero_in_tx(
                tx,
                &rebind,
                |_| Err(PackCommitError::Invalid("wire rebinding must not build a plan")),
                deadline(),
            )
            .await?
            .into_parts();
        let error = error.unwrap_err();
        assert!(matches!(error, PackCommitError::RefStore(RefStoreError::DigestConflict)));
        tx.rollback().await?;
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn slot_zero_replay_rejects_missing_or_wrong_producer_binding() -> anyhow::Result<()> {
    with_fixture(|fixture| async move {
        let public = Uuid::new_v4();
        let private = Uuid::new_v4();
        let request = slot_zero_request(&fixture, public, private);
        let plan_digest = RequestDigest::from_bytes([7; 32]);
        let proof = proof_digest(&ProofFacts {
            request: &request,
            private_id: private,
            sequence: 1,
            base_revision: 1,
            plan_digest,
        });
        let mut client = fixture.pool.get().await?;

        let tx = tokio_postgres::Client::transaction(&mut client).await?;
        seed_wrapper_without_binding(&tx, &fixture, &request, plan_digest, proof).await?;
        let (tx, error) = PgRefStore
            .admit_slot_zero_in_tx(
                tx,
                &request,
                |_| Err(PackCommitError::Invalid("a replay must not build a plan")),
                deadline(),
            )
            .await?
            .into_parts();
        let error = error.unwrap_err();
        assert_ledger_integrity(&error, "slot zero serving producer binding is missing");
        tx.rollback().await?;

        let tx = tokio_postgres::Client::transaction(&mut client).await?;
        seed_wrapper_without_binding(&tx, &fixture, &request, plan_digest, proof).await?;
        tx.execute(
            "INSERT INTO ref_store_serving_operations(
                     repository_id,operation_id,issuer_id,producer_request_digest,plan_parent_digest)
                 VALUES($1,$2,$3,$4,$5)",
            &[&fixture.repo, &private, &fixture.actor, &"d".repeat(64), &plan_digest.as_hex()],
        )
        .await?;
        let (tx, error) = PgRefStore
            .admit_slot_zero_in_tx(
                tx,
                &request,
                |_| Err(PackCommitError::Invalid("a replay must not build a plan")),
                deadline(),
            )
            .await?
            .into_parts();
        let error = error.unwrap_err();
        assert_ledger_integrity(&error, "slot zero serving producer binding differs from the wrapper");
        tx.rollback().await?;
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn slot_zero_rollback_leaves_no_sequence_or_half_binding_and_rejects_overflow() -> anyhow::Result<()> {
    with_fixture(|fixture| async move {
        let public = Uuid::new_v4();
        let private = Uuid::new_v4();
        let request = slot_zero_request(&fixture, public, private);
        let mut client = fixture.pool.get().await?;

        let tx = tokio_postgres::Client::transaction(&mut client).await?;
        let (tx, receipt) = PgRefStore
            .admit_slot_zero_in_tx(tx, &request, |preview| plan_for(&fixture, &request, preview), deadline())
            .await?
            .into_parts();
        let receipt = receipt?;
        assert_eq!(receipt.sequence, 1);
        tx.rollback().await?;

        let wrappers: i64 = client
            .query_one("SELECT count(*) FROM ref_store_public_operations WHERE repository_id=$1", &[&fixture.repo])
            .await?
            .get(0);
        let lanes: i64 = client
            .query_one("SELECT count(*) FROM ref_store_issuer_lanes WHERE repository_id=$1", &[&fixture.repo])
            .await?
            .get(0);
        let operations: i64 = client
            .query_one("SELECT count(*) FROM ref_store_operations WHERE repository_id=$1", &[&fixture.repo])
            .await?
            .get(0);
        let bindings: i64 = client
            .query_one("SELECT count(*) FROM ref_store_serving_operations WHERE repository_id=$1", &[&fixture.repo])
            .await?
            .get(0);
        assert_eq!((wrappers, lanes, operations, bindings), (0, 0, 0, 0));

        let tx = tokio_postgres::Client::transaction(&mut client).await?;
        let (tx, receipt) = PgRefStore
            .admit_slot_zero_in_tx(tx, &request, |preview| plan_for(&fixture, &request, preview), deadline())
            .await?
            .into_parts();
        let receipt = receipt?;
        assert_eq!(receipt.sequence, 1);
        tx.commit().await?;

        let overflow_lane = IssuerLane::new("overflow").unwrap();
        let max = i64::MAX;
        client
            .execute(
                "INSERT INTO ref_store_issuer_lanes(repository_id,issuer_id,lane,last_reserved_sequence)
                     VALUES($1,$2,$3,$4)",
                &[&fixture.repo, &fixture.actor, &overflow_lane.as_str(), &max],
            )
            .await?;
        let mut overflow = slot_zero_request(&fixture, Uuid::new_v4(), Uuid::new_v4());
        overflow.lane = overflow_lane.clone();
        let tx = tokio_postgres::Client::transaction(&mut client).await?;
        let (tx, error) = PgRefStore
            .admit_slot_zero_in_tx(
                tx,
                &overflow,
                |_| Err(PackCommitError::Invalid("overflow must not build a plan")),
                deadline(),
            )
            .await?
            .into_parts();
        let error = error.unwrap_err();
        assert!(matches!(error, PackCommitError::RefStore(RefStoreError::Database(_))));
        tx.rollback().await?;
        let last: i64 = client
            .query_one(
                "SELECT last_reserved_sequence FROM ref_store_issuer_lanes
                     WHERE repository_id=$1 AND issuer_id=$2 AND lane=$3",
                &[&fixture.repo, &fixture.actor, &overflow_lane.as_str()],
            )
            .await?
            .get(0);
        assert_eq!(last, max);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn slot_zero_typed_plan_error_rolls_back_only_the_savepoint() -> anyhow::Result<()> {
    with_fixture(|fixture| async move {
        let lane = IssuerLane::new("slot-zero-atomic").unwrap();
        let public = Uuid::new_v4();
        let private = Uuid::new_v4();
        let mut request = slot_zero_request(&fixture, public, private);
        request.lane = lane.clone();
        let mut client = fixture.pool.get().await?;
        let tx = tokio_postgres::Client::transaction(&mut client).await?;

        // The unique lane is absent, so preview inserts last_reserved_sequence=0
        // before build_plan returns this typed error.
        let (tx, error) = PgRefStore
            .admit_slot_zero_in_tx(
                tx,
                &request,
                |_| Err(PackCommitError::Invalid("slot zero plan rejected after preview")),
                deadline(),
            )
            .await?
            .into_parts();
        let error = error.unwrap_err();
        match error {
            PackCommitError::Invalid("slot zero plan rejected after preview") => {}
            other => panic!("expected the original typed plan error, got {other:?}"),
        }

        // The outer transaction must still be usable: commit unrelated work.
        let marker = Uuid::new_v4();
        tx.execute(
            "INSERT INTO users(id,username) VALUES($1,$2)",
            &[&marker, &format!("slotzeroafter{}", &marker.simple().to_string()[..12])],
        )
        .await?;
        tx.commit().await?;

        let committed: bool =
            client.query_one("SELECT EXISTS(SELECT 1 FROM users WHERE id=$1)", &[&marker]).await?.get(0);
        assert!(committed, "unrelated outer transaction work must commit");

        let row = client
            .query_one(
                "SELECT
                   (SELECT count(*) FROM ref_store_issuer_lanes
                     WHERE repository_id=$1 AND issuer_id=$2 AND lane=$3),
                   (SELECT count(*) FROM ref_store_public_operations
                     WHERE repository_id=$1 AND public_id=$4),
                   (SELECT count(*) FROM ref_store_private_attempts
                     WHERE repository_id=$1 AND private_id=$5),
                   (SELECT count(*) FROM ref_store_operations
                     WHERE repository_id=$1 AND operation_id=$5),
                   (SELECT count(*) FROM ref_store_serving_operations
                     WHERE repository_id=$1 AND operation_id=$5)",
                &[&fixture.repo, &fixture.actor, &lane.as_str(), &public, &private],
            )
            .await?;
        for index in 0..5usize {
            assert_eq!(row.get::<_, i64>(index), 0, "slot-zero savepoint rollback left a row in column {index}");
        }
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn slot_zero_cancelled_owned_tx_cannot_be_committed() -> anyhow::Result<()> {
    with_fixture(|fixture| async move {
        let lane = IssuerLane::new("slot-zero").unwrap();
        let seed = fixture.pool.get().await?;
        seed.execute(
            "INSERT INTO ref_store_issuer_lanes(repository_id,issuer_id,lane,last_reserved_sequence)
                 VALUES($1,$2,$3,0)",
            &[&fixture.repo, &fixture.actor, &lane.as_str()],
        )
        .await?;
        drop(seed);

        // Real uncommitted row lock: the admission future blocks in the owned
        // outer transaction and cannot reach RELEASE while this holder lives.
        let mut holder_client = fixture.pool.get().await?;
        let holder_tx = tokio_postgres::Client::transaction(&mut holder_client).await?;
        let holder_pid: i32 = holder_tx.query_one("SELECT pg_backend_pid()", &[]).await?.get(0);
        holder_tx
            .query_one(
                "SELECT last_reserved_sequence FROM ref_store_issuer_lanes
                 WHERE repository_id=$1 AND issuer_id=$2 AND lane=$3 FOR UPDATE",
                &[&fixture.repo, &fixture.actor, &lane.as_str()],
            )
            .await?;

        let public = Uuid::new_v4();
        let private = Uuid::new_v4();
        let request = slot_zero_request(&fixture, public, private);
        let worker_fixture = fixture.clone();
        let worker_request = request.clone();
        let worker_pool = fixture.pool.clone();
        let (pid_tx, pid_rx) = oneshot::channel();
        let mut admission: tokio::task::JoinHandle<anyhow::Result<()>> = tokio::spawn(async move {
            let mut client = worker_pool.get().await?;
            let tx = tokio_postgres::Client::transaction(&mut client).await?;
            let pid: i32 = tx.query_one("SELECT pg_backend_pid()", &[]).await?.get(0);
            let _ = pid_tx.send(pid);
            let admission = PgRefStore
                .admit_slot_zero_in_tx(
                    tx,
                    &worker_request,
                    |preview| plan_for(&worker_fixture, &worker_request, preview),
                    deadline(),
                )
                .await?;
            // This must not be reached while the lane lock is held. Dropping the
            // returned transaction still rolls it back; returning Err makes the
            // contract violation visible to the test.
            drop(admission);
            Err(anyhow::anyhow!("slot-zero admission returned while the lane lock was still held"))
        });

        let admission_pid =
            timeout(WAIT, pid_rx).await.context("cancelled admission never reported its backend pid")??;
        let observer = fixture.pool.get().await?;
        timeout(WAIT, async {
            loop {
                let waiting: bool = observer
                    .query_one(
                        "SELECT EXISTS(SELECT 1 FROM pg_stat_activity a
                         WHERE a.pid=$1 AND a.state='active' AND a.wait_event_type='Lock'
                           AND a.query LIKE 'SELECT last_reserved_sequence + 1 FROM ref_store_issuer_lanes%'
                           AND $2 = ANY(pg_blocking_pids($1)))",
                        &[&admission_pid, &holder_pid],
                    )
                    .await?
                    .get(0);
                if waiting {
                    break Ok::<(), anyhow::Error>(());
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .context("cancelled admission never blocked on the held lane lock")??;

        // Cancel the future while it owns the outer transaction. The caller
        // never receives a SlotZeroAdmission for this path; the dropped future
        // owns and rolls back the outer transaction.
        admission.abort();
        match timeout(WAIT, &mut admission).await {
            Ok(Err(error)) if error.is_cancelled() => {}
            Ok(Ok(_worker_result)) => return Err(anyhow::anyhow!("aborted admission unexpectedly returned normally")),
            Ok(Err(error)) => return Err(error.into()),
            Err(_) => return Err(anyhow::anyhow!("aborted admission task did not join")),
        }

        holder_tx.rollback().await?;
        timeout(WAIT, async {
            loop {
                let clear: bool = observer
                    .query_one(
                        "SELECT NOT EXISTS(
                             SELECT 1 FROM pg_locks l JOIN pg_class c ON c.oid=l.relation
                             WHERE l.pid=$1 AND l.granted
                               AND c.relname IN ('cluster_authority','ref_store_issuer_lanes',
                                                 'repositories','ref_store_core_gates'))",
                        &[&admission_pid],
                    )
                    .await?
                    .get(0);
                if clear {
                    break Ok::<(), anyhow::Error>(());
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .context("cancelled admission backend kept an admission lock")??;

        let row = observer
            .query_one(
                "SELECT
                   (SELECT count(*) FROM ref_store_public_operations WHERE repository_id=$1),
                   (SELECT count(*) FROM ref_store_private_attempts WHERE repository_id=$1),
                   (SELECT count(*) FROM ref_store_operations WHERE repository_id=$1),
                   (SELECT count(*) FROM ref_store_serving_operations WHERE repository_id=$1),
                   (SELECT last_reserved_sequence FROM ref_store_issuer_lanes
                     WHERE repository_id=$1 AND issuer_id=$2 AND lane=$3)",
                &[&fixture.repo, &fixture.actor, &lane.as_str()],
            )
            .await?;
        for index in 0..4usize {
            assert_eq!(row.get::<_, i64>(index), 0, "cancelled ownership boundary left a row in column {index}");
        }
        assert_eq!(row.get::<_, i64>(4), 0, "cancelled admission advanced the issuer lane");
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn slot_zero_restore_rotation_waits_for_admission_commit() -> anyhow::Result<()> {
    with_fixture(|fixture| async move {
        let request = slot_zero_request(&fixture, Uuid::new_v4(), Uuid::new_v4());
        let mut admission = fixture.pool.get().await?;
        let tx = tokio_postgres::Client::transaction(&mut admission).await?;
        let (tx, receipt) = PgRefStore
            .admit_slot_zero_in_tx(tx, &request, |preview| plan_for(&fixture, &request, preview), deadline())
            .await?
            .into_parts();
        let receipt = receipt?;
        assert_eq!(receipt.sequence, 1);
        let mut tx = Some(tx);
        let admission_pid: i32 = tx
            .as_ref()
            .expect("admission transaction must exist")
            .query_one("SELECT pg_backend_pid()", &[])
            .await?
            .get(0);

        let restore_pool = fixture.pool.clone();
        let (pid_tx, pid_rx) = oneshot::channel();
        let (done_tx, done_rx) = oneshot::channel();
        let mut restore = tokio::spawn(async move {
            let mut client = restore_pool.get().await?;
            let tx = tokio_postgres::Client::transaction(&mut client).await?;
            let pid: i32 = tx.query_one("SELECT pg_backend_pid()", &[]).await?.get(0);
            let _ = pid_tx.send(pid);
            let changed = tx
                .execute(
                    "UPDATE public.cluster_authority SET incarnation=gen_random_uuid(),rotated_at=clock_timestamp()
                     WHERE singleton=true",
                    &[],
                )
                .await?;
            let _ = done_tx.send(changed);
            tx.commit().await?;
            Ok::<(), anyhow::Error>(())
        });

        let mut restore_joined = false;
        let outcome: anyhow::Result<()> = async {
            let restore_pid =
                timeout(WAIT, pid_rx).await.context("restore worker never reported its backend pid")??;
            let observer = timeout(WAIT, fixture.pool.get()).await.context("observer pool checkout timed out")??;
            timeout(WAIT, async {
                loop {
                    let waiting: bool = observer
                        .query_one(
                            "SELECT EXISTS(
                                 SELECT 1 FROM pg_stat_activity a
                                 WHERE a.pid=$1 AND a.state='active' AND a.wait_event_type='Lock'
                                   AND a.query LIKE 'UPDATE public.cluster_authority%'
                                   AND $2 = ANY(pg_blocking_pids($1)))",
                            &[&restore_pid, &admission_pid],
                        )
                        .await?
                        .get(0);
                    if waiting {
                        break Ok::<(), anyhow::Error>(());
                    }
                    sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .context("restore wait probe did not finish")??;

            let owned = tx.take().ok_or_else(|| anyhow::anyhow!("admission transaction missing before commit"))?;
            timeout(WAIT, owned.commit()).await.context("admission commit did not finish")??;

            let joined = timeout(WAIT, &mut restore).await.context("restore worker did not finish")?;
            restore_joined = true;
            joined.context("restore worker panicked")??;

            let changed = timeout(WAIT, done_rx).await.context("restore result did not arrive")??;
            if changed != 1 {
                return Err(anyhow::anyhow!("restore UPDATE changed {changed} rows, expected 1"));
            }
            Ok(())
        }
        .await;

        if let Err(mut error) = outcome {
            if !restore_joined {
                error = append_cleanup(error, "restore worker abort/join", abort_worker(&mut restore).await);
            }
            if let Some(owned) = tx.take() {
                error = append_cleanup(error, "admission rollback", rollback_bounded(owned).await);
            }
            return Err(error);
        }
        if let Some(owned) = tx.take() {
            let error = anyhow::anyhow!("admission transaction remained uncommitted after a successful outcome");
            let cleanup = rollback_bounded(owned).await;
            return Err(append_cleanup(error, "admission rollback", cleanup));
        }
        drop(tx);

        let incarnation: Uuid = timeout(
            WAIT,
            admission.query_one("SELECT incarnation FROM public.cluster_authority WHERE singleton=true", &[]),
        )
        .await
        .context("rotated incarnation query did not finish")??
        .get(0);
        if incarnation == fixture.restore {
            return Err(anyhow::anyhow!("restore rotation did not change the cluster authority incarnation"));
        }
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn slot_zero_waits_for_legacy_lane_before_scope_and_gate() -> anyhow::Result<()> {
    with_fixture(|fixture| async move {
        let lane = IssuerLane::new("slot-zero").unwrap();
        let seed = fixture.pool.get().await?;
        seed.execute(
            "INSERT INTO ref_store_issuer_lanes(repository_id,issuer_id,lane,last_reserved_sequence)
                 VALUES($1,$2,$3,0)",
            &[&fixture.repo, &fixture.actor, &lane.as_str()],
        )
        .await?;
        drop(seed);
        let legacy_private = Uuid::new_v4();
        let legacy_identity = OperationIdentity::new(
            fixture.repo,
            fixture.actor,
            lane,
            1,
            legacy_private,
            RequestDigest::from_bytes([42; 32]),
        )
        .map_err(PackCommitError::from)?;
        let mut legacy_client = fixture.pool.get().await?;
        let mut legacy_tx = Some(tokio_postgres::Client::transaction(&mut legacy_client).await?);
        let legacy_pid: i32 = {
            let legacy_tx_ref = legacy_tx.as_ref().expect("legacy transaction must exist");
            let _legacy = PgRefStore.begin(legacy_tx_ref, &legacy_identity, deadline()).await?;
            legacy_tx_ref.query_one("SELECT pg_backend_pid()", &[]).await?.get(0)
        };

        let request = slot_zero_request(&fixture, Uuid::new_v4(), Uuid::new_v4());
        let admission_fixture = fixture.clone();
        let (pid_tx, pid_rx) = oneshot::channel();
        let (done_tx, done_rx) = oneshot::channel();
        let mut admission = tokio::spawn(async move {
            let mut client = admission_fixture.pool.get().await?;
            let tx = tokio_postgres::Client::transaction(&mut client).await?;
            let pid: i32 = tx.query_one("SELECT pg_backend_pid()", &[]).await?.get(0);
            let _ = pid_tx.send(pid);
            let (tx, receipt) = PgRefStore
                .admit_slot_zero_in_tx(
                    tx,
                    &request,
                    |preview| plan_for(&admission_fixture, &request, preview),
                    deadline(),
                )
                .await?
                .into_parts();
            let receipt = receipt?;
            tx.commit().await?;
            let _ = done_tx.send(receipt);
            Ok::<(), anyhow::Error>(())
        });

        let mut admission_joined = false;
        let outcome: anyhow::Result<()> = async {
            let admission_pid =
                timeout(WAIT, pid_rx).await.context("slot-zero worker never reported its backend pid")??;
            let observer = timeout(WAIT, fixture.pool.get()).await.context("observer pool checkout timed out")??;
            timeout(WAIT, async {
                loop {
                    let row = observer
                        .query_one(
                            "SELECT
                               EXISTS(SELECT 1 FROM pg_stat_activity a
                                 WHERE a.pid=$1 AND a.state='active' AND a.wait_event_type='Lock'
                                   AND a.query LIKE 'SELECT last_reserved_sequence + 1 FROM ref_store_issuer_lanes%'
                                   AND $2 = ANY(pg_blocking_pids($1))),
                               EXISTS(SELECT 1 FROM pg_locks l JOIN pg_class c ON c.oid=l.relation
                                 WHERE l.pid=$1 AND l.granted AND l.mode <> 'AccessShareLock'
                                   AND c.relname IN ('repositories','ref_store_core_gates'))",
                            &[&admission_pid, &legacy_pid],
                        )
                        .await?;
                    let waiting: bool = row.get(0);
                    let scope_locked: bool = row.get(1);
                    if waiting {
                        if scope_locked {
                            return Err(anyhow::anyhow!(
                                "slot-zero took repository/gate locks before waiting for the legacy lane"
                            ));
                        }
                        break Ok::<(), anyhow::Error>(());
                    }
                    sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .context("slot-zero lane wait probe did not finish")??;

            let owned = legacy_tx.take().ok_or_else(|| anyhow::anyhow!("legacy transaction missing before commit"))?;
            timeout(WAIT, owned.commit()).await.context("legacy lane commit did not finish")??;

            let joined = timeout(WAIT, &mut admission).await.context("slot-zero admission did not finish")?;
            admission_joined = true;
            joined.context("slot-zero admission task panicked")??;

            let receipt = timeout(WAIT, done_rx).await.context("slot-zero admission result did not arrive")??;
            if receipt.sequence != 2 {
                return Err(anyhow::anyhow!("slot-zero admission reserved {}, expected 2", receipt.sequence));
            }
            Ok(())
        }
        .await;

        if let Err(mut error) = outcome {
            if !admission_joined {
                error = append_cleanup(error, "slot-zero admission abort/join", abort_worker(&mut admission).await);
            }
            if let Some(owned) = legacy_tx.take() {
                error = append_cleanup(error, "legacy rollback", rollback_bounded(owned).await);
            }
            return Err(error);
        }
        if let Some(owned) = legacy_tx.take() {
            let error = anyhow::anyhow!("legacy transaction remained uncommitted after a successful outcome");
            let cleanup = rollback_bounded(owned).await;
            return Err(append_cleanup(error, "legacy rollback", cleanup));
        }
        Ok(())
    })
    .await
}

fn sample_request() -> SlotZeroAdmissionRequest {
    SlotZeroAdmissionRequest {
        repository_id: Uuid::from_bytes([1; 16]),
        admission_owner_id: Uuid::from_bytes([2; 16]),
        issuer_id: Uuid::from_bytes([3; 16]),
        lane: IssuerLane::new("slot-zero").unwrap(),
        public_id: Uuid::from_bytes([4; 16]),
        private_id: Uuid::from_bytes([5; 16]),
        wire_digest: RequestDigest::from_bytes([6; 32]),
        request_mode: CommitMode::Atomic,
        backend_identity: "a".repeat(64),
        object_format: GitObjectFormat::Sha1,
        history_incarnation: Uuid::from_bytes([7; 16]),
        authority_epoch: 1,
        group_epoch: 1,
        restore_incarnation: Uuid::from_bytes([8; 16]),
    }
}

#[test]
fn slot_zero_request_rejects_equal_ids_and_noncanonical_backend() {
    let request = sample_request();
    assert!(validate_request(&request).is_ok());
    let mut equal = request.clone();
    equal.private_id = equal.public_id;
    assert!(matches!(validate_request(&equal), Err(RefStoreError::InvalidIdentity(_))));
    let mut backend = request.clone();
    backend.backend_identity = "A".repeat(64);
    assert!(matches!(validate_request(&backend), Err(RefStoreError::InvalidIdentity(_))));
    let mut nil = request;
    nil.issuer_id = Uuid::nil();
    assert!(matches!(validate_request(&nil), Err(RefStoreError::InvalidIdentity(_))));
}

#[test]
fn slot_zero_proof_binds_sequence_plan_and_wire() {
    let request = sample_request();
    let plan = RequestDigest::from_bytes([9; 32]);
    let baseline = ProofFacts {
        request: &request,
        private_id: request.private_id,
        sequence: 1,
        base_revision: 1,
        plan_digest: plan,
    };
    let proof = proof_digest(&baseline);
    assert_eq!(proof, proof_digest(&baseline));
    assert_ne!(
        proof,
        proof_digest(&ProofFacts {
            request: &request,
            private_id: request.private_id,
            sequence: 2,
            base_revision: 1,
            plan_digest: plan,
        })
    );
    let mut rebound = request.clone();
    rebound.wire_digest = RequestDigest::from_bytes([10; 32]);
    assert_ne!(
        proof,
        proof_digest(&ProofFacts {
            request: &rebound,
            private_id: rebound.private_id,
            sequence: 1,
            base_revision: 1,
            plan_digest: plan,
        })
    );
    assert_ne!(
        proof,
        proof_digest(&ProofFacts {
            request: &request,
            private_id: request.private_id,
            sequence: 1,
            base_revision: 1,
            plan_digest: RequestDigest::from_bytes([11; 32]),
        })
    );
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn slot_zero_fixture_setup_error_drops_only_its_owned_database() -> anyhow::Result<()> {
    let base_url = std::env::var("ROOTYARD_TEST_DATABASE_URL")?;
    let admin = db::pool(&base_url)?;
    let observed = Arc::new(Mutex::new(None));
    let captured = Arc::clone(&observed);
    let error = match fixture_with_setup_check(move |database| {
        *captured.lock().expect("fixture database capture lock poisoned") = Some(database.to_string());
        Err(anyhow::anyhow!("injected setup failure after fixture seed"))
    })
    .await
    {
        Ok(_) => return Err(anyhow::anyhow!("injected setup failure unexpectedly produced a fixture")),
        Err(error) => error,
    };
    let database = {
        let mut captured = observed.lock().expect("fixture database capture lock poisoned");
        captured.take().ok_or_else(|| anyhow::anyhow!("fixture did not report its owned database name"))?
    };
    let chain = format!("{error:#}");
    assert!(
        chain.contains("injected setup failure after fixture seed"),
        "setup cleanup replaced the original error: {chain}"
    );
    assert!(!chain.contains("fixture setup database cleanup"), "setup cleanup failed: {chain}");
    let admin_client =
        timeout(WAIT, admin.get()).await.context("setup database absence admin checkout did not finish")??;
    let exists: bool = timeout(
        WAIT,
        admin_client.query_one("SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname=$1)", &[&database]),
    )
    .await
    .context("setup database absence query did not finish")??
    .get(0);
    assert!(!exists, "owned setup database {database} survived cleanup");
    Ok(())
}

#[derive(Debug, Eq, PartialEq)]
struct AttemptLedgerFacts {
    wrappers: i64,
    attempts: i64,
    operations: i64,
    bindings: i64,
    lanes: i64,
    cancellations: i64,
    events: i64,
    gate_revision: i64,
    restore_incarnation: Uuid,
}

async fn attempt_ledger_facts(
    client: &tokio_postgres::Client,
    fixture: &Fixture,
) -> anyhow::Result<AttemptLedgerFacts> {
    let row = client
        .query_one(
            "SELECT
               (SELECT count(*) FROM ref_store_public_operations WHERE repository_id=$1),
               (SELECT count(*) FROM ref_store_private_attempts WHERE repository_id=$1),
               (SELECT count(*) FROM ref_store_operations WHERE repository_id=$1),
               (SELECT count(*) FROM ref_store_serving_operations WHERE repository_id=$1),
               (SELECT count(*) FROM ref_store_issuer_lanes WHERE repository_id=$1),
               (SELECT count(*) FROM ref_store_cancellations WHERE repository_id=$1),
               (SELECT count(*) FROM ref_store_core_events WHERE repository_id=$1),
               (SELECT revision FROM ref_store_core_gates WHERE repository_id=$1),
               (SELECT incarnation FROM public.cluster_authority WHERE singleton)",
            &[&fixture.repo],
        )
        .await?;
    Ok(AttemptLedgerFacts {
        wrappers: row.get(0),
        attempts: row.get(1),
        operations: row.get(2),
        bindings: row.get(3),
        lanes: row.get(4),
        cancellations: row.get(5),
        events: row.get(6),
        gate_revision: row.get(7),
        restore_incarnation: row.get(8),
    })
}

fn public_attempt_request(fixture: &Fixture, admission: &SlotZeroAdmissionRequest) -> PublicAttemptRequest {
    PublicAttemptRequest {
        repository_id: fixture.repo,
        admission_owner_id: fixture.actor,
        issuer_id: fixture.actor,
        public_id: admission.public_id,
        wire_digest: admission.wire_digest,
        request_mode: admission.request_mode,
        backend_identity: fixture.backend.clone(),
        object_format: admission.object_format,
        history_incarnation: fixture.history,
        authority_epoch: admission.authority_epoch,
        group_epoch: admission.group_epoch,
        restore_incarnation: fixture.restore,
    }
}

/// Exact wrapper/attempt/operation/event rows for one public operation. This
/// compares the durable ledger after the mirror and after its read-only replay.
async fn public_terminal_ledger(
    client: &tokio_postgres::Client,
    repository_id: Uuid,
    public_id: Uuid,
) -> anyhow::Result<serde_json::Value> {
    let row = client
        .query_one(
            "SELECT jsonb_build_object(
               'wrapper', (SELECT to_jsonb(w)
                             FROM ref_store_public_operations w
                            WHERE w.repository_id=$1 AND w.public_id=$2),
               'attempts', (SELECT jsonb_agg(to_jsonb(a) ORDER BY a.slot)
                              FROM ref_store_private_attempts a
                             WHERE a.repository_id=$1 AND a.public_id=$2),
               'operation', (SELECT to_jsonb(o)
                               FROM ref_store_operations o
                               JOIN ref_store_private_attempts a
                                 ON a.repository_id=o.repository_id AND a.private_id=o.operation_id
                              WHERE a.repository_id=$1 AND a.public_id=$2),
               'event', (SELECT to_jsonb(e)
                           FROM ref_store_core_events e
                           JOIN ref_store_private_attempts a
                             ON a.repository_id=e.repository_id AND a.private_id=e.operation_id
                          WHERE a.repository_id=$1 AND a.public_id=$2),
               'gate_revision', (SELECT revision FROM ref_store_core_gates WHERE repository_id=$1),
               'event_count', (SELECT count(*) FROM ref_store_core_events WHERE repository_id=$1)
             )",
            &[&repository_id, &public_id],
        )
        .await?;
    Ok(row.get(0))
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn slot_zero_public_attempt_lookup_is_exact_and_read_only() -> anyhow::Result<()> {
    with_fixture(|fixture| async move {
        let public = Uuid::new_v4();
        let private = Uuid::new_v4();
        let admission_request = slot_zero_request(&fixture, public, private);
        let mut client = fixture.pool.get().await?;
        let mut admitted_plan = None;

        let tx = tokio_postgres::Client::transaction(&mut client).await?;
        let (tx, receipt) = PgRefStore
            .admit_slot_zero_in_tx(
                tx,
                &admission_request,
                |preview| {
                    let plan = plan_for(&fixture, &admission_request, preview)?;
                    admitted_plan = Some(plan.clone());
                    Ok(plan)
                },
                deadline(),
            )
            .await?
            .into_parts();
        let receipt = receipt?;
        assert!(!receipt.replayed);
        assert_eq!(receipt.public_id, public);
        assert_eq!(receipt.private_id, private);
        assert_eq!(receipt.sequence, 1);
        assert_eq!(receipt.state, OperationState::Pending);
        tx.commit().await?;

        let migrations = client
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=147),
                        EXISTS(SELECT 1 FROM schema_migrations WHERE version=152)",
                &[],
            )
            .await?;
        assert!(migrations.get::<_, bool>(0), "fixture must include migration 147");
        assert!(migrations.get::<_, bool>(1), "fixture must include migration 152");

        let live_restore: Uuid =
            client.query_one("SELECT incarnation FROM public.cluster_authority WHERE singleton", &[]).await?.get(0);
        assert_eq!(live_restore, fixture.restore, "fixture restore incarnation must still be current");

        let binding = client
            .query_one(
                "SELECT producer_request_digest,plan_parent_digest
                   FROM ref_store_serving_operations
                  WHERE repository_id=$1 AND operation_id=$2",
                &[&fixture.repo, &private],
            )
            .await?;
        assert_eq!(binding.get::<_, String>(0), admission_request.wire_digest.as_hex());
        assert_eq!(binding.get::<_, String>(1), receipt.plan_digest.as_hex());

        let lookup_request = PublicAttemptRequest {
            repository_id: fixture.repo,
            admission_owner_id: fixture.actor,
            issuer_id: fixture.actor,
            public_id: public,
            wire_digest: admission_request.wire_digest,
            request_mode: admission_request.request_mode,
            backend_identity: fixture.backend.clone(),
            object_format: admission_request.object_format,
            history_incarnation: fixture.history,
            authority_epoch: admission_request.authority_epoch,
            group_epoch: admission_request.group_epoch,
            restore_incarnation: fixture.restore,
        };
        assert_eq!(lookup_request.public_id, public);
        assert_eq!(lookup_request.admission_owner_id, fixture.actor);
        assert_eq!(lookup_request.restore_incarnation, fixture.restore);
        assert_eq!(lookup_request.wire_digest, receipt.wire_digest);

        let before = attempt_ledger_facts(&client, &fixture).await?;
        let admitted_plan = admitted_plan.context("slot zero did not build a plan")?;
        let tx = tokio_postgres::Client::transaction(&mut client).await?;
        assert!(matches!(
            PgRefStore.begin(&tx, admitted_plan.identity(), deadline()).await,
            Err(RefStoreError::IdentityConflict)
        ));
        tx.rollback().await?;

        let tx = tokio_postgres::Client::transaction(&mut client).await?;
        PgRefStore.lock_private_pending_attempt(&tx, &lookup_request, &admitted_plan, deadline()).await?;
        tx.commit().await?;

        let tx = tokio_postgres::Client::transaction(&mut client).await?;
        tx.batch_execute("SET TRANSACTION READ ONLY").await?;
        let read_only: String = tx.query_one("SHOW transaction_read_only", &[]).await?.get(0);
        assert_eq!(read_only, "on", "lookup smoke must use a read-only transaction");

        match PgRefStore.lookup_public_attempt(&tx, &lookup_request, deadline()).await? {
            PublicAttemptLookup::Pending(evidence) => {
                assert_eq!(evidence.public_id, public);
                assert!(evidence.retired.is_none());
                assert_eq!(evidence.current.slot, 0);
                assert_eq!(evidence.current.private_id, private);
                assert_eq!(evidence.current.plan_digest, receipt.plan_digest);
                assert_eq!(evidence.current.proof_digest, receipt.proof_digest);
                assert_eq!(evidence.current.base_revision, receipt.base_revision);
                assert_eq!(evidence.current.lane, admission_request.lane);
                assert_eq!(evidence.current.sequence, receipt.sequence);
                assert_eq!(evidence.current.state, OperationState::Pending);
                assert!(evidence.current.event_id.is_none());
                assert!(evidence.current.event_revision.is_none());
            }
            other => panic!("expected pending public attempt, got {other:?}"),
        }

        let mut unknown_request = lookup_request.clone();
        unknown_request.public_id = Uuid::new_v4();
        assert_eq!(
            PgRefStore.lookup_public_attempt(&tx, &unknown_request, deadline()).await?,
            PublicAttemptLookup::Unknown
        );

        let mut wrong_wire = lookup_request.clone();
        wrong_wire.wire_digest = RequestDigest::from_bytes([2; 32]);
        match PgRefStore.lookup_public_attempt(&tx, &wrong_wire, deadline()).await {
            Err(PackCommitError::RefStore(RefStoreError::DigestConflict)) => {}
            other => {
                return Err(anyhow::anyhow!(
                    "wrong-wire public attempt lookup did not return DigestConflict: {other:?}"
                ));
            }
        }

        tx.rollback().await?;
        let tx = tokio_postgres::Client::transaction(&mut client).await?;
        assert!(matches!(
            PgRefStore.lock_private_pending_attempt(&tx, &wrong_wire, &admitted_plan, deadline()).await,
            Err(PackCommitError::RefStore(RefStoreError::DigestConflict))
        ));
        tx.rollback().await?;

        let tx = tokio_postgres::Client::transaction(&mut client).await?;
        assert!(matches!(
            PgRefStore.lock_private_pending_attempt(&tx, &unknown_request, &admitted_plan, deadline()).await,
            Err(PackCommitError::RefStore(RefStoreError::IdentityConflict))
        ));
        tx.rollback().await?;

        let after = attempt_ledger_facts(&client, &fixture).await?;
        assert_eq!(before, after, "public attempt lookup or prefix lock changed the attempt ledger");
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn slot_zero_public_terminal_mirror_commits_then_exactly_replays() -> anyhow::Result<()> {
    with_fixture(|fixture| async move {
        let public = Uuid::new_v4();
        let private = Uuid::new_v4();
        let admission_request = slot_zero_request(&fixture, public, private);
        let mut client = fixture.pool.get().await?;

        // Real slot-zero admission: wrapper + slot-zero attempt + pending
        // migration-138 operation + migration-147 producer binding.
        let tx = tokio_postgres::Client::transaction(&mut client).await?;
        let (tx, receipt) = PgRefStore
            .admit_slot_zero_in_tx(
                tx,
                &admission_request,
                |preview| plan_for(&fixture, &admission_request, preview),
                deadline(),
            )
            .await?
            .into_parts();
        let receipt = receipt?;
        assert!(!receipt.replayed);
        assert_eq!(receipt.state, OperationState::Pending);
        tx.commit().await?;

        let public_request = public_attempt_request(&fixture, &admission_request);
        let identity = OperationIdentity::new(
            fixture.repo,
            fixture.actor,
            admission_request.lane.clone(),
            receipt.sequence,
            private,
            receipt.plan_digest,
        )?;

        // A still-pending private operation is refused before any SQL lock or
        // write. The outer transaction remains usable for its rollback.
        let pending_ledger = public_terminal_ledger(&client, fixture.repo, public).await?;
        let pending_tx = tokio_postgres::Client::transaction(&mut client).await?;
        let pending_record = match PgRefStore.get(&pending_tx, fixture.repo, private, deadline()).await? {
            OperationLookup::Known(record) => record,
            OperationLookup::Unknown => return Err(anyhow::anyhow!("admitted private operation is not registered")),
        };
        assert_eq!(pending_record.state(), OperationState::Pending);
        match PgRefStore
            .mirror_public_attempt_terminal_in_tx(&pending_tx, &public_request, &pending_record, deadline())
            .await
        {
            Err(PackCommitError::RefStore(RefStoreError::OperationPending { operation_id }))
                if operation_id == private => {}
            other => {
                return Err(anyhow::anyhow!(
                    "pending terminal mirror did not fail closed with OperationPending: {other:?}"
                ));
            }
        }
        pending_tx.rollback().await?;
        assert_eq!(
            public_terminal_ledger(&client, fixture.repo, public).await?,
            pending_ledger,
            "pending terminal mirror changed the public ledger"
        );

        // The existing core adapter writes both immutable pieces: the exact
        // migration-138 terminal and the migration-139 event body. A full
        // commit_refs/authorized commit is the wrong seam here because this ready
        // fixture realm is decision-required and the authorized path additionally
        // requires a native closure proof.
        let terminal = CommitTerminal::rejected(
            fixture.repo,
            receipt.base_revision,
            Some("refs/heads/main".into()),
            vec![RefCommitResult::NotApplied {
                name: "refs/heads/main".into(),
                reason: CommitRejectCode::OldOidMismatch,
            }],
            CommitRejection {
                code: CommitRejectCode::OldOidMismatch,
                ref_name: Some("refs/heads/main".into()),
                expected: None,
                actual: None,
            },
        );
        let result = terminal.to_terminal_result()?;
        let terminal_tx = tokio_postgres::Client::transaction(&mut client).await?;
        let terminal_receipt =
            PgRefStore.record_terminal(&terminal_tx, &identity, TerminalOutcome::Rejected, &result, deadline()).await?;
        assert!(!terminal_receipt.replayed);
        assert_eq!(terminal_receipt.record.state(), OperationState::Rejected);
        crate::ref_store::core::sql::insert_event(
            &terminal_tx,
            fixture.repo,
            receipt.base_revision,
            private,
            "rejected",
            &result,
        )
        .await?;
        let event_id: Uuid = terminal_tx
            .query_one(
                "SELECT event_id FROM ref_store_core_events WHERE repository_id=$1 AND operation_id=$2",
                &[&fixture.repo, &private],
            )
            .await?
            .get(0);
        terminal_tx.commit().await?;

        // Wrong wire identity fails before the guarded UPDATE and leaves the
        // exact pending wrapper/terminal/event ledger unchanged.
        let mut wrong_wire = public_request.clone();
        wrong_wire.wire_digest = RequestDigest::from_bytes([2; 32]);
        let before_wrong_wire = public_terminal_ledger(&client, fixture.repo, public).await?;
        let wrong_tx = tokio_postgres::Client::transaction(&mut client).await?;
        match PgRefStore
            .mirror_public_attempt_terminal_in_tx(&wrong_tx, &wrong_wire, &terminal_receipt.record, deadline())
            .await
        {
            Err(PackCommitError::RefStore(RefStoreError::DigestConflict)) => {}
            other => {
                return Err(anyhow::anyhow!(
                    "wrong-wire terminal mirror did not fail closed with DigestConflict: {other:?}"
                ));
            }
        }
        wrong_tx.rollback().await?;
        assert_eq!(
            public_terminal_ledger(&client, fixture.repo, public).await?,
            before_wrong_wire,
            "wrong-wire terminal mirror changed the public ledger"
        );

        // Fresh short owned transaction: the mirror publishes the exact
        // already-durable state/event id and the caller's COMMIT is the point.
        let commit_tx = tokio_postgres::Client::transaction(&mut client).await?;
        let mirrored = match PgRefStore
            .mirror_public_attempt_terminal_in_tx(&commit_tx, &public_request, &terminal_receipt.record, deadline())
            .await?
        {
            PublicAttemptTerminalOutcome::Mirrored(receipt) => receipt,
            other => return Err(anyhow::anyhow!("terminal mirror unexpectedly required retirement: {other:?}")),
        };
        assert!(!mirrored.replayed);
        assert_eq!(mirrored.state, OperationState::Rejected);
        assert_eq!(mirrored.event_id, event_id);
        commit_tx.commit().await?;

        let wrapper = client
            .query_one(
                "SELECT state,event_id,current_slot,retired_event_id,cancelled_private_id
                   FROM ref_store_public_operations
                  WHERE repository_id=$1 AND public_id=$2",
                &[&fixture.repo, &public],
            )
            .await?;
        assert_eq!(wrapper.get::<_, String>(0), "rejected");
        assert_eq!(wrapper.get::<_, Option<Uuid>>(1), Some(event_id));
        assert_eq!(wrapper.get::<_, i16>(2), 0);
        assert_eq!(wrapper.get::<_, Option<Uuid>>(3), None);
        assert_eq!(wrapper.get::<_, Option<Uuid>>(4), None);

        let event = client
            .query_one(
                "SELECT event_id,revision,outcome,payload
                   FROM ref_store_core_events
                  WHERE repository_id=$1 AND operation_id=$2",
                &[&fixture.repo, &private],
            )
            .await?;
        assert_eq!(event.get::<_, Uuid>(0), event_id);
        assert_eq!(event.get::<_, i64>(1), receipt.base_revision);
        assert_eq!(event.get::<_, String>(2), "rejected");
        assert_eq!(&event.get::<_, serde_json::Value>(3), result.value());

        // Exact replay in another fresh short owned transaction returns the same
        // durable event and changes no wrapper/attempt/operation/event row.
        let before_replay = public_terminal_ledger(&client, fixture.repo, public).await?;
        let replay_tx = tokio_postgres::Client::transaction(&mut client).await?;
        let replayed = match PgRefStore
            .mirror_public_attempt_terminal_in_tx(&replay_tx, &public_request, &terminal_receipt.record, deadline())
            .await?
        {
            PublicAttemptTerminalOutcome::Mirrored(receipt) => receipt,
            other => return Err(anyhow::anyhow!("exact terminal replay unexpectedly required retirement: {other:?}")),
        };
        assert!(replayed.replayed);
        assert_eq!(replayed.state, OperationState::Rejected);
        assert_eq!(replayed.event_id, event_id);
        replay_tx.commit().await?;
        assert_eq!(
            public_terminal_ledger(&client, fixture.repo, public).await?,
            before_replay,
            "exact terminal mirror replay changed the public ledger"
        );
        Ok(())
    })
    .await
}
