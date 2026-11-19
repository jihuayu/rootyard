//! Deterministic PostgreSQL acceptance for the private slot-zero gateway
//! first-lane lock order (`#42`).
//!
//! The case calls the real crate-private gateway adapter
//! [`super::publish::begin_slot_zero`], not the ref-store lane helper alone.
//! It seeds one run-owned repository through the real serving provision API,
//! captures the real core baseline, and opens one separate owning transaction
//! that inserts the expected issuer lane row without committing it.
//!
//! The gateway then runs its actual public preflight. Its fresh route must
//! block in `INSERT ... ON CONFLICT` for that first lane row **before** it
//! reads the repository or serving binding. The test observes the gateway
//! backend through `pg_stat_activity`/`pg_blocking_pids` while it waits. A
//! third, independent authority transaction then takes `FOR NO KEY UPDATE` on
//! both rows under a short `lock_timeout`. That mode deliberately remains
//! compatible with the first lane insert's foreign-key `FOR KEY SHARE` but
//! conflicts with the serving lookup's `FOR SHARE`; if the gateway waiter had
//! taken authority locks first, the third transaction could not finish.
//!
//! Only after those observations is the owned lane transaction committed. The
//! naturally completed admission must reserve issuer sequence 1 and create the
//! exact wrapper/attempt/operation/binding rows. An exact pending replay and a
//! stale-baseline refusal then must leave every ledger row and the issuer
//! sequence byte-for-byte unchanged; the stale refusal must return the typed
//! rebaseline answer rather than publish a partial admission.
//!
//! The fixture owns one fresh PostgreSQL database and drops it after the run;
//! its repository/issuer scope and the in-process `cfg(test)` memory Blob
//! store are likewise run-only. No S3, HTTP route, environment-selected seam
//! or production runtime is activated. Every owned transaction is committed or
//! rolled back under the same bounded wait, a still-blocked gateway task is
//! aborted and joined, and the database is dropped only after every local pool
//! is closed. Run explicitly by Root (the role needs `CREATEDB`):
//!
//! ```text
//! ROOTYARD_TEST_DATABASE_URL=... ROOTYARD_TEST_GIT=/usr/bin/git \
//! cargo test --lib slot_zero_admission_acceptance -- --ignored --test-threads=1
//! ```

use std::{panic::AssertUnwindSafe, sync::Arc, time::Duration};

use anyhow::{Context, Result, anyhow, ensure};
use deadpool_postgres::{Manager, Pool, Runtime};
use futures_util::FutureExt;
use serde_json::Value;
use tokio::{
    task::JoinHandle,
    time::{Instant, sleep, timeout},
};
use uuid::Uuid;

use super::{
    BlobGitConfig, BlobGitState, GatewayError,
    protocol::{PushCommand, PushRequest},
    publish::{Start, begin_slot_zero},
    session_http_acceptance::fixtures::{actor, git::Git},
    snapshot::capture_baseline,
};
use crate::{
    blob_store::{budget::ResourceLimits, test_support},
    db,
    ref_store::{
        CommitMode, GitObjectFormat, IssuerLane, RequestDigest,
        core::{
            CoreGate,
            pack_commit::{PackCommitBaseline, PackCommitPlan},
        },
        pg::{OPERATION_LOCK_DOMAIN, OPERATION_LOCK_SQL},
        serving::{self, ProvisionRequest, ServingRepository},
    },
};

const WAIT: Duration = Duration::from_secs(15);
const ISSUER_LANE: &str = "blob-git-receive";
/// The third authority probe must fail fast rather than inherit the fixture's
/// longer statement/lock budget. The outer `WAIT` still bounds checkout and
/// rollback around this explicitly shorter lock bound.
const AUTHORITY_LOCK_TIMEOUT_SQL: &str = "SET LOCAL lock_timeout = '2000ms'";

/// One positive wait observation. The observed backend is the dedicated
/// gateway pool (unique `application_name`), is active inside the exact
/// first-lane INSERT, names the fixture creator as its blocker, and already
/// holds its real transaction advisory locks. The creator likewise holds its
/// published operation advisory key. Elapsed time, global SQL text or an
/// unfinished task alone is never the identity/evidence. The separate
/// authority transaction below proves the lock-order property: the lane
/// INSERT's foreign-key `FOR KEY SHARE` is compatible with its
/// `FOR NO KEY UPDATE`, while a pre-lane serving `FOR SHARE` is not.
const LANE_WAIT_PROBE: &str = "SELECT
        a.pid,
        pg_blocking_pids(a.pid),
        EXISTS(
            SELECT 1 FROM pg_locks l
            WHERE l.pid=$1 AND l.locktype='advisory' AND l.granted
        ) AS creator_holds_operation_key,
        EXISTS(
            SELECT 1 FROM pg_locks l
            WHERE l.pid=a.pid AND l.locktype='advisory' AND l.granted
        ) AS waiter_holds_operation_key
    FROM pg_stat_activity a
    WHERE a.datname=current_database()
      AND a.application_name=$2
      AND a.state='active' AND a.wait_event_type='Lock'
      AND $1::int = ANY(pg_blocking_pids(a.pid))
      AND a.query LIKE 'INSERT INTO ref_store_issuer_lanes%'";

/// Every durable row this admission can write, in one stable snapshot. Exact
/// replay and the stale-baseline refusal must not change this value.
const LEDGER_SNAPSHOT: &str = "SELECT jsonb_build_object(
        'wrapper', COALESCE((
            SELECT jsonb_agg(to_jsonb(w) ORDER BY w.public_id)
            FROM ref_store_public_operations w WHERE w.repository_id=$1
        ), '[]'::jsonb),
        'attempts', COALESCE((
            SELECT jsonb_agg(to_jsonb(a) ORDER BY a.public_id, a.slot)
            FROM ref_store_private_attempts a WHERE a.repository_id=$1
        ), '[]'::jsonb),
        'operations', COALESCE((
            SELECT jsonb_agg(to_jsonb(o) ORDER BY o.operation_id)
            FROM ref_store_operations o WHERE o.repository_id=$1
        ), '[]'::jsonb),
        'bindings', COALESCE((
            SELECT jsonb_agg(to_jsonb(s) ORDER BY s.operation_id)
            FROM ref_store_serving_operations s WHERE s.repository_id=$1
        ), '[]'::jsonb),
        'lanes', COALESCE((
            SELECT jsonb_agg(to_jsonb(l) ORDER BY l.issuer_id, l.lane)
            FROM ref_store_issuer_lanes l WHERE l.repository_id=$1
        ), '[]'::jsonb),
        'cancellations', COALESCE((
            SELECT jsonb_agg(to_jsonb(c) ORDER BY c.operation_id)
            FROM ref_store_cancellations c WHERE c.repository_id=$1
        ), '[]'::jsonb),
        'events', COALESCE((
            SELECT jsonb_agg(to_jsonb(e) ORDER BY e.event_id)
            FROM ref_store_core_events e WHERE e.repository_id=$1
        ), '[]'::jsonb),
        'refs', COALESCE((
            SELECT jsonb_agg(to_jsonb(r) ORDER BY r.ref_name)
            FROM ref_store_core_refs r WHERE r.repository_id=$1
        ), '[]'::jsonb),
        'gate', (SELECT to_jsonb(g) FROM ref_store_core_gates g WHERE g.repository_id=$1)
    )";

#[tokio::test]
#[ignore = "requires CREATEDB, ROOTYARD_TEST_DATABASE_URL, Linux procfs and an executable Git"]
async fn first_lane_insert_waits_before_authority_locks() -> Result<()> {
    let application_name = format!("issue42_slot0_gateway_{}", Uuid::new_v4().simple());
    let (admin, database, pool, gateway_pool) = setup_owned_database(&application_name).await?;
    let outcome = AssertUnwindSafe(case(&pool, &gateway_pool, &application_name)).catch_unwind().await;
    pool.close();
    gateway_pool.close();
    drop(pool);
    drop(gateway_pool);
    let cleanup = timeout(WAIT, cleanup_owned_database(&admin, &database))
        .await
        .context("owned database cleanup did not finish")?;
    match outcome {
        Ok(result) => match (result, cleanup) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) => Err(error),
            (Ok(()), Err(error)) => Err(error),
            (Err(error), Err(cleanup_error)) => Err(append_cleanup(error, "owned database cleanup", cleanup_error)),
        },
        Err(payload) => {
            if let Err(error) = cleanup {
                eprintln!("owned slot-zero admission database cleanup failed: {error:#}");
            }
            std::panic::resume_unwind(payload)
        }
    }
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(120)
}

fn append_cleanup(mut error: anyhow::Error, label: &str, cleanup: anyhow::Error) -> anyhow::Error {
    error = anyhow!("{error:#}; {label} also failed: {cleanup:#}");
    error
}

async fn setup_owned_database(application_name: &str) -> Result<(Pool, String, Pool, Pool)> {
    let base_url =
        std::env::var("ROOTYARD_TEST_DATABASE_URL").context("ROOTYARD_TEST_DATABASE_URL must name the owned server")?;
    let admin = db::pool(&base_url).context("owned database admin pool rejected")?;
    let database = format!("slot_zero_{}", Uuid::new_v4().simple());

    // CREATE is the ownership linearization point. Record the name only after an
    // acknowledged success, exactly like the existing owned slot-zero fixture.
    let create = timeout(WAIT, admin.get()).await.context("owned database CREATE admin checkout did not finish")??;
    timeout(WAIT, create.batch_execute(&format!("CREATE DATABASE {database}")))
        .await
        .context("owned database CREATE did not finish")??;
    drop(create);

    let setup: Result<(Pool, Pool)> = async {
        let mut config: tokio_postgres::Config = base_url.parse()?;
        config.dbname(database.as_str());
        config.options("-c search_path=public -c timezone=UTC -c statement_timeout=15000 -c lock_timeout=10000");
        let pool = Pool::builder(Manager::new(config.clone(), tokio_postgres::NoTls))
            .runtime(Runtime::Tokio1)
            .max_size(8)
            .build()?;
        config.application_name(application_name);
        let gateway_pool =
            Pool::builder(Manager::new(config, tokio_postgres::NoTls)).runtime(Runtime::Tokio1).max_size(8).build()?;
        db::migrate(&pool).await?;
        Ok((pool, gateway_pool))
    }
    .await;

    match setup {
        Ok((pool, gateway_pool)) => Ok((admin, database, pool, gateway_pool)),
        Err(original) => {
            let cleanup = cleanup_owned_database(&admin, &database).await;
            Err(match cleanup {
                Ok(()) => original,
                Err(cleanup_error) => append_cleanup(original, "database setup cleanup", cleanup_error),
            })
        }
    }
}

async fn cleanup_owned_database(admin: &Pool, database: &str) -> Result<()> {
    let client = timeout(WAIT, admin.get()).await.context("owned database cleanup admin checkout did not finish")??;
    timeout(
        WAIT,
        client.query(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity
             WHERE datname=$1 AND pid<>pg_backend_pid()",
            &[&database],
        ),
    )
    .await
    .context("owned database backend termination did not finish")??;
    timeout(WAIT, client.batch_execute(&format!("DROP DATABASE {database}")))
        .await
        .context("owned database DROP did not finish")??;
    Ok(())
}

async fn case(db: &Pool, gateway_pool: &Pool, gateway_application_name: &str) -> Result<()> {
    let resources =
        ResourceLimits::new(2, 2, 1 << 20).map_err(|error| anyhow!("memory Blob budget rejected: {error}"))?;
    let (store, _resources) = test_support::store(resources);
    let git = Git::new()?;
    let scratch = tempfile::tempdir().context("temporary gateway scratch root")?;
    let state = Arc::new(
        BlobGitState::new(BlobGitConfig {
            pool: (*gateway_pool).clone(),
            store: store.clone(),
            git_binary: git.binary().to_path_buf(),
            scratch_root: scratch.path().to_path_buf(),
            max_concurrent_requests: 4,
            max_request_bytes: 16 * 1024 * 1024,
            max_response_bytes: 64 * 1024 * 1024,
            max_inflight_bytes: 64 * 1024 * 1024,
            operation_deadline: Duration::from_secs(120),
            native_limits: Default::default(),
        })
        .map_err(|error| anyhow!("gateway configuration refused: {error}"))?,
    );

    let owner = actor::owner(db).await?;
    let name = format!("slot-zero-first-lane-{}", &Uuid::new_v4().simple().to_string()[..12]);
    serving::provision(
        db,
        &owner.identity,
        ProvisionRequest { owner: None, name: name.clone(), object_format: GitObjectFormat::Sha1 },
        store.backend_identity(),
        deadline(),
    )
    .await
    .map_err(|error| anyhow!("serving provision refused: {error}"))?;
    let serving =
        serving::lookup(db, &owner.identity, &owner.username, &name, true, store.backend_identity(), deadline())
            .await
            .map_err(|error| anyhow!("serving lookup refused: {error}"))?;
    let repository_id = serving.gate.repository_id();
    let backend_identity = store.backend_identity().as_hex();
    let baseline = capture_baseline(&state, repository_id, serving.gate.tenant_id(), deadline())
        .await
        .map_err(|error| anyhow!("initial baseline capture refused: {error:?}"))?;

    let public_id = Uuid::new_v4();
    let creator_operation = Uuid::new_v4();
    ensure!(creator_operation != public_id, "the lane creator and gateway waiter reused one operation advisory key");
    let producer = RequestDigest::of("issue42-private-first-lane", &[public_id.as_bytes(), name.as_bytes()]);
    let request = PushRequest {
        commands: vec![PushCommand { old: "0".repeat(40), new: "a".repeat(40), name: "refs/heads/main".to_owned() }],
        capabilities: vec!["report-status".to_owned()],
    };
    let mode = CommitMode::Atomic;
    let lane = IssuerLane::new(ISSUER_LANE).map_err(|error| anyhow!("issuer lane rejected: {error:?}"))?;

    // The separate owning transaction is the only creator of this lane row.
    // Its uncommitted INSERT is the lock the real gateway must wait behind.
    let mut lane_client = checkout(db, "lane creator").await?;
    let mut lane_tx = Some(
        timeout(WAIT, tokio_postgres::Client::transaction(&mut lane_client))
            .await
            .context("lane creator BEGIN did not finish")??,
    );
    let lane_pid: i32 = {
        let tx = lane_tx.as_ref().ok_or_else(|| anyhow!("lane creator transaction was not created"))?;
        // The creator is a real operation participant: take the published
        // migration-138 operation advisory key before touching the initially
        // absent lane. The gateway waiter uses a different public operation id.
        timeout(WAIT, tx.query_one(OPERATION_LOCK_SQL, &[&OPERATION_LOCK_DOMAIN, &repository_id, &creator_operation]))
            .await
            .context("lane creator operation advisory lock did not finish")??;
        let existing: i64 = timeout(
            WAIT,
            tx.query_one(
                "SELECT count(*) FROM ref_store_issuer_lanes
                 WHERE repository_id=$1 AND issuer_id=$2 AND lane=$3",
                &[&repository_id, &owner.identity.id, &lane.as_str()],
            ),
        )
        .await
        .context("initial issuer-lane absence check did not finish")??
        .get(0);
        ensure!(existing == 0, "the owned fixture already contained the expected issuer lane");
        timeout(
            WAIT,
            tx.execute(
                "INSERT INTO ref_store_issuer_lanes(repository_id,issuer_id,lane,last_reserved_sequence)
                 VALUES($1,$2,$3,0)",
                &[&repository_id, &owner.identity.id, &lane.as_str()],
            ),
        )
        .await
        .context("lane creator INSERT did not finish")??;
        timeout(WAIT, tx.query_one("SELECT pg_backend_pid()", &[]))
            .await
            .context("lane creator pid query did not finish")??
            .get(0)
    };

    let mut waiter: Option<JoinHandle<std::result::Result<Start, GatewayError>>> = None;
    let outcome = AssertUnwindSafe(async {
        let state_for_wait = Arc::clone(&state);
        let serving_for_wait = serving.clone();
        let actor_for_wait = owner.identity.clone();
        let request_for_wait = request.clone();
        let baseline_for_wait = baseline.clone();
        waiter = Some(tokio::spawn(async move {
            begin_slot_zero(
                &state_for_wait,
                &serving_for_wait,
                &actor_for_wait,
                public_id,
                producer,
                &request_for_wait,
                &[],
                mode,
                &baseline_for_wait,
                deadline(),
            )
            .await
        }));

        // Positive evidence: the gateway is in the first-lane INSERT, blocked
        // by the creator. The independent authority transaction below then
        // proves it has not taken repository/binding locks.
        observe_blocked_first_lane(db, lane_pid, gateway_application_name, &mut waiter).await?;

        // A third, independent authority transaction can lock both rows while
        // the gateway waiter is still parked. This is the regression: the lane
        // wait must happen before any repository/binding authority lock.
        third_authority_can_lock(db, repository_id).await?;
        observe_blocked_first_lane(db, lane_pid, gateway_application_name, &mut waiter).await?;

        let owned = lane_tx.take().ok_or_else(|| anyhow!("lane creator transaction was already consumed"))?;
        timeout(WAIT, owned.commit()).await.context("lane creator COMMIT did not finish")??;

        let handle = waiter.as_mut().ok_or_else(|| anyhow!("gateway waiter task was not created"))?;
        let start = timeout(WAIT, handle).await.context("gateway waiter did not finish after the lane commit")??;
        waiter = None;
        let plan = match start {
            Ok(Start::Fresh { plan, .. }) => plan,
            Ok(_) => return Err(anyhow!("gateway admission did not return a fresh pending plan")),
            Err(error) => return Err(anyhow!("gateway admission was refused: {error:?}")),
        };

        assert_natural_admission(
            db,
            repository_id,
            public_id,
            producer,
            plan.as_ref(),
            &serving,
            owner.identity.id,
            backend_identity.as_str(),
            baseline.gate().revision(),
        )
        .await?;
        let natural_counts = ledger_effect_counts(db, repository_id).await?;
        ensure!(
            natural_counts == [1, 1, 1, 1, 0, 0, 0],
            "natural admission wrote unexpected ledger effect counts: {natural_counts:?}"
        );
        let natural = ledger_snapshot(db, repository_id).await?;

        // Exact replay of the still-pending public identity must resolve as an
        // unknown outcome, not allocate a second sequence or rewrite any row.
        let replay = begin_slot_zero(
            &state,
            &serving,
            &owner.identity,
            public_id,
            producer,
            &request,
            &[],
            mode,
            &baseline,
            deadline(),
        )
        .await;
        ensure!(
            matches!(replay, Err(GatewayError::OutcomeUnknown)),
            "an exact pending replay did not return the typed unknown outcome"
        );
        ensure!(
            ledger_effect_counts(db, repository_id).await? == natural_counts,
            "an exact pending replay changed the ledger effect counts"
        );
        ensure!(
            ledger_snapshot(db, repository_id).await? == natural,
            "an exact pending replay changed the issuer sequence or admission ledger"
        );

        // A distinct public identity with a stale captured revision must take
        // the typed rebaseline refusal and publish no wrapper, attempt,
        // operation, binding or sequence.
        let rejected_public = Uuid::new_v4();
        ensure!(rejected_public != public_id, "the rejected fixture reused the natural public operation key");
        let rejected_producer =
            RequestDigest::of("issue42-private-first-lane-rejected", &[rejected_public.as_bytes(), name.as_bytes()]);
        let stale_gate = CoreGate::new(
            serving.gate.repository_id(),
            serving.gate.tenant_id(),
            serving.gate.object_format(),
            serving.gate.history_incarnation(),
            serving.gate.authority_epoch(),
            serving.gate.group_epoch(),
            serving.gate.head_ref().clone(),
            serving.gate.revision() + 1,
        )
        .map_err(|error| anyhow!("stale gate fixture rejected: {error:?}"))?;
        let stale_baseline = PackCommitBaseline::new(
            stale_gate.version(),
            baseline.mode(),
            baseline.refs().to_vec(),
            baseline.old_packs().to_vec(),
        )
        .map_err(|error| anyhow!("stale baseline fixture rejected: {error:?}"))?;
        let rejected = begin_slot_zero(
            &state,
            &serving,
            &owner.identity,
            rejected_public,
            rejected_producer,
            &request,
            &[],
            mode,
            &stale_baseline,
            deadline(),
        )
        .await;
        ensure!(
            matches!(rejected, Ok(Start::Rebaseline)),
            "the stale-baseline public identity did not take the typed rebaseline refusal"
        );
        ensure!(
            ledger_effect_counts(db, repository_id).await? == natural_counts,
            "the stale-baseline refusal changed the ledger effect counts"
        );
        ensure!(
            ledger_snapshot(db, repository_id).await? == natural,
            "the stale-baseline refusal changed the issuer sequence or admission ledger"
        );

        Ok::<(), anyhow::Error>(())
    })
    .catch_unwind()
    .await;

    let mut cleanup = Vec::new();
    if let Some(handle) = waiter.as_mut() {
        if let Err(error) = abort_worker(handle).await {
            cleanup.push(format!("gateway waiter abort/join: {error:#}"));
        }
    }
    if let Some(owned) = lane_tx.take() {
        if let Err(error) = rollback_bounded(owned).await {
            cleanup.push(format!("lane creator rollback: {error:#}"));
        }
    }

    match outcome {
        Ok(Ok(())) => {
            if cleanup.is_empty() {
                Ok(())
            } else {
                Err(anyhow!("fixture cleanup failed: {}", cleanup.join("; ")))
            }
        }
        Ok(Err(error)) => {
            if cleanup.is_empty() {
                Err(error)
            } else {
                Err(anyhow!("{error:#}; fixture cleanup also failed: {}", cleanup.join("; ")))
            }
        }
        Err(payload) => {
            if !cleanup.is_empty() {
                eprintln!("slot-zero admission witness cleanup failed: {}", cleanup.join("; "));
            }
            std::panic::resume_unwind(payload)
        }
    }
}

async fn checkout(pool: &Pool, label: &str) -> Result<deadpool_postgres::Client> {
    match timeout(WAIT, pool.get()).await {
        Ok(Ok(client)) => Ok(client),
        Ok(Err(_)) => Err(anyhow!("{label} pool checkout failed")),
        Err(_) => Err(anyhow!("{label} pool checkout did not finish within {WAIT:?}")),
    }
}

async fn rollback_bounded(tx: tokio_postgres::Transaction<'_>) -> Result<()> {
    match timeout(WAIT, tx.rollback()).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(anyhow!("owned transaction rollback failed: {error}")),
        Err(_) => Err(anyhow!("owned transaction rollback did not finish within {WAIT:?}")),
    }
}

async fn abort_worker<T>(worker: &mut JoinHandle<T>) -> Result<()> {
    worker.abort();
    match timeout(WAIT, &mut *worker).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(error)) if error.is_cancelled() => Ok(()),
        Ok(Err(error)) => Err(anyhow!("gateway waiter task could not be joined: {error}")),
        Err(_) => Err(anyhow!("gateway waiter task did not join within {WAIT:?}")),
    }
}

async fn observe_blocked_first_lane(
    pool: &Pool,
    lane_pid: i32,
    gateway_application_name: &str,
    waiter: &mut Option<JoinHandle<std::result::Result<Start, GatewayError>>>,
) -> Result<()> {
    let observer = checkout(pool, "lane witness").await?;
    timeout(WAIT, async {
        loop {
            if waiter.as_ref().is_some_and(|handle| handle.is_finished()) {
                let handle = waiter.take().ok_or_else(|| anyhow!("gateway waiter task was lost"))?;
                let joined = timeout(WAIT, handle).await.context("gateway waiter join did not finish")?;
                let joined = joined.context("gateway waiter task could not be joined")?;
                return match joined {
                    Ok(Start::Fresh { .. }) => {
                        Err(anyhow!("gateway admission completed before waiting on the first lane insert"))
                    }
                    Ok(_) => Err(anyhow!(
                        "gateway admission returned an unexpected start before waiting on the first lane insert"
                    )),
                    Err(error) => {
                        Err(anyhow!("gateway admission was refused before waiting on the first lane insert: {error:?}"))
                    }
                };
            }
            ensure!(waiter.is_some(), "gateway waiter task was lost before the first lane insert was observed");
            let row = observer.query_opt(LANE_WAIT_PROBE, &[&lane_pid, &gateway_application_name]).await?;
            if let Some(row) = row {
                let waiter_pid: i32 = row.get(0);
                let blockers: Vec<i32> = row.get(1);
                let creator_holds_operation_key: bool = row.get(2);
                let waiter_holds_operation_key: bool = row.get(3);
                ensure!(waiter_pid != lane_pid, "the lane creator was mistaken for the blocked gateway waiter");
                ensure!(
                    blockers.contains(&lane_pid),
                    "the gateway waiter's blocker dependency does not name the lane creator"
                );
                ensure!(
                    creator_holds_operation_key,
                    "the lane creator does not hold its published operation advisory key"
                );
                ensure!(
                    waiter_holds_operation_key,
                    "the gateway waiter has not taken its operation advisory key before the lane wait"
                );
                return Ok::<(), anyhow::Error>(());
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .context("gateway waiter did not enter the blocked first-lane INSERT within the bound")??;
    Ok(())
}

async fn third_authority_can_lock(pool: &Pool, repository_id: Uuid) -> Result<()> {
    let mut client = checkout(pool, "third authority").await?;
    let tx = timeout(WAIT, tokio_postgres::Client::transaction(&mut client))
        .await
        .context("third authority BEGIN did not finish")??;
    let outcome = timeout(WAIT, async {
        tx.execute(AUTHORITY_LOCK_TIMEOUT_SQL, &[]).await?;
        // `FOR NO KEY UPDATE` is the authority write lock here. It conflicts with
        // the serving lookup's `FOR SHARE`, but not with the creator lane INSERT's
        // foreign-key `FOR KEY SHARE` on the same repository row.
        let repository =
            tx.query_one("SELECT id FROM repositories WHERE id=$1 FOR NO KEY UPDATE", &[&repository_id]).await?;
        ensure!(repository.get::<_, Uuid>(0) == repository_id, "third authority locked another repository row");
        let binding = tx
            .query_one(
                "SELECT repository_id FROM ref_store_serving_repositories WHERE repository_id=$1 FOR NO KEY UPDATE",
                &[&repository_id],
            )
            .await?;
        ensure!(binding.get::<_, Uuid>(0) == repository_id, "third authority locked another serving binding row");
        Ok::<(), anyhow::Error>(())
    })
    .await;
    let outcome = match outcome {
        Ok(result) => result,
        Err(_) => Err(anyhow!("third authority did not lock repository/binding within {WAIT:?}")),
    };
    let rollback = match timeout(WAIT, tx.rollback()).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(anyhow!("third authority rollback failed: {error}")),
        Err(_) => Err(anyhow!("third authority rollback did not finish within {WAIT:?}")),
    };
    outcome.and(rollback)
}

async fn ledger_snapshot(pool: &Pool, repository_id: Uuid) -> Result<Value> {
    let client = checkout(pool, "ledger snapshot").await?;
    let row = timeout(WAIT, client.query_one(LEDGER_SNAPSHOT, &[&repository_id]))
        .await
        .context("ledger snapshot did not finish")??;
    Ok(row.get(0))
}

/// Wrapper, attempt, operation, binding, cancellation, event and ref row counts.
/// Exact replay/refusal must leave every one of these unchanged; the natural
/// admission has exactly one of each first four and none of the last three.
async fn ledger_effect_counts(pool: &Pool, repository_id: Uuid) -> Result<[i64; 7]> {
    let client = checkout(pool, "ledger effect counts").await?;
    let row = timeout(
        WAIT,
        client.query_one(
            "SELECT
                 (SELECT count(*) FROM ref_store_public_operations WHERE repository_id=$1),
                 (SELECT count(*) FROM ref_store_private_attempts WHERE repository_id=$1),
                 (SELECT count(*) FROM ref_store_operations WHERE repository_id=$1),
                 (SELECT count(*) FROM ref_store_serving_operations WHERE repository_id=$1),
                 (SELECT count(*) FROM ref_store_cancellations WHERE repository_id=$1),
                 (SELECT count(*) FROM ref_store_core_events WHERE repository_id=$1),
                 (SELECT count(*) FROM ref_store_core_refs WHERE repository_id=$1)",
            &[&repository_id],
        ),
    )
    .await
    .context("ledger effect count did not finish")??;
    Ok([
        row.get::<_, i64>(0),
        row.get::<_, i64>(1),
        row.get::<_, i64>(2),
        row.get::<_, i64>(3),
        row.get::<_, i64>(4),
        row.get::<_, i64>(5),
        row.get::<_, i64>(6),
    ])
}

#[allow(clippy::too_many_arguments)]
async fn assert_natural_admission(
    pool: &Pool,
    repository_id: Uuid,
    public_id: Uuid,
    producer: RequestDigest,
    plan: &PackCommitPlan,
    serving: &ServingRepository,
    issuer_id: Uuid,
    backend_identity: &str,
    baseline_revision: i64,
) -> Result<()> {
    let client = checkout(pool, "natural admission witness").await?;
    let row = timeout(
        WAIT,
        client.query_one(
            "SELECT
                 w.state AS wrapper_state,
                 w.current_slot AS current_slot,
                 w.issuer_id AS issuer_id,
                 w.admission_owner_id AS admission_owner_id,
                 w.wire_digest AS wire_digest,
                 w.request_mode AS request_mode,
                 w.backend_identity AS backend_identity,
                 w.object_format AS object_format,
                 w.history_incarnation AS history_incarnation,
                 w.authority_epoch AS authority_epoch,
                 w.group_epoch AS group_epoch,
                 w.restore_incarnation AS restore_incarnation,
                 a.private_id AS private_id,
                 a.plan_digest AS plan_digest,
                 a.proof_digest AS proof_digest,
                 a.base_revision AS base_revision,
                 o.lane AS lane,
                 o.sequence AS issuer_sequence,
                 o.request_digest AS operation_request_digest,
                 o.state AS operation_state,
                 s.producer_request_digest AS producer_request_digest,
                 s.plan_parent_digest AS plan_parent_digest,
                 l.last_reserved_sequence AS last_reserved_sequence,
                 g.revision AS gate_revision
             FROM ref_store_public_operations w
             JOIN ref_store_private_attempts a
               ON a.repository_id=w.repository_id AND a.public_id=w.public_id AND a.slot=w.current_slot
             JOIN ref_store_operations o
               ON o.repository_id=a.repository_id AND o.operation_id=a.private_id
             JOIN ref_store_serving_operations s
               ON s.repository_id=o.repository_id AND s.operation_id=o.operation_id
             JOIN ref_store_issuer_lanes l
               ON l.repository_id=o.repository_id AND l.issuer_id=o.issuer_id AND l.lane=o.lane
             JOIN ref_store_core_gates g ON g.repository_id=w.repository_id
             WHERE w.repository_id=$1 AND w.public_id=$2",
            &[&repository_id, &public_id],
        ),
    )
    .await
    .context("natural admission witness did not finish")??;

    let identity = plan.identity();
    ensure!(row.get::<_, String>("wrapper_state") == "pending", "natural wrapper is not pending");
    ensure!(row.get::<_, i16>("current_slot") == 0, "natural wrapper did not start at slot zero");
    ensure!(row.get::<_, Uuid>("issuer_id") == issuer_id, "natural wrapper recorded another issuer");
    ensure!(
        row.get::<_, Uuid>("admission_owner_id") == serving.gate.tenant_id(),
        "natural wrapper recorded another admission owner"
    );
    ensure!(
        row.get::<_, String>("wire_digest") == producer.as_hex(),
        "natural wrapper did not retain the producer request digest"
    );
    ensure!(row.get::<_, String>("request_mode") == "atomic", "natural wrapper recorded another request mode");
    ensure!(
        row.get::<_, String>("backend_identity").as_str() == backend_identity,
        "natural wrapper recorded another Blob backend identity"
    );
    ensure!(row.get::<_, String>("object_format") == "sha1", "natural wrapper recorded another object format");
    ensure!(
        row.get::<_, Uuid>("history_incarnation") == plan.history_incarnation(),
        "natural wrapper recorded another history incarnation"
    );
    ensure!(
        row.get::<_, i64>("authority_epoch") == plan.authority_epoch()
            && row.get::<_, i64>("group_epoch") == plan.group_epoch(),
        "natural wrapper recorded another authority/group epoch"
    );
    ensure!(
        row.get::<_, Uuid>("restore_incarnation") == serving.cluster_incarnation,
        "natural wrapper recorded another restore incarnation"
    );
    ensure!(
        row.get::<_, Uuid>("private_id") == identity.operation_id(),
        "natural private attempt differs from the admitted plan"
    );
    ensure!(
        row.get::<_, i64>("issuer_sequence") == 1 && identity.sequence() == 1,
        "natural admission did not reserve the first issuer sequence"
    );
    ensure!(
        row.get::<_, String>("plan_digest") == plan.parent_digest().as_hex(),
        "natural attempt recorded another canonical plan digest"
    );
    let proof_digest: String = row.get("proof_digest");
    ensure!(
        proof_digest.len() == 64 && proof_digest.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "natural attempt has no canonical proof digest"
    );
    ensure!(
        row.get::<_, i64>("base_revision") == plan.expected().revision()
            && plan.expected().revision() == baseline_revision,
        "natural attempt recorded another base revision"
    );
    ensure!(row.get::<_, String>("lane") == ISSUER_LANE, "natural operation recorded another issuer lane");
    ensure!(
        row.get::<_, i64>("last_reserved_sequence") == row.get::<_, i64>("issuer_sequence"),
        "issuer lane head differs from the migration-138 operation sequence"
    );
    ensure!(
        row.get::<_, String>("operation_request_digest") == plan.parent_digest().as_hex(),
        "natural operation did not bind the canonical plan parent digest"
    );
    ensure!(row.get::<_, String>("operation_state") == "pending", "natural operation is not pending");
    ensure!(
        row.get::<_, String>("producer_request_digest") == producer.as_hex(),
        "natural producer binding lost the exact request digest"
    );
    ensure!(
        row.get::<_, String>("plan_parent_digest") == plan.parent_digest().as_hex(),
        "natural producer binding lost the plan parent digest"
    );
    ensure!(
        row.get::<_, i64>("last_reserved_sequence") == 1,
        "natural admission did not advance the issuer lane exactly once"
    );
    ensure!(row.get::<_, i64>("gate_revision") == baseline_revision, "admission advanced the core gate revision");

    Ok(())
}
