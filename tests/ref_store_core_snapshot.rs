//! Real-PostgreSQL contract tests for the metadata-only snapshot/pin core (A2).
//!
//! Run explicitly by the root runner:
//! `ROOTYARD_TEST_DATABASE_URL=... cargo test --test ref_store_core_snapshot -- --ignored`.
//! Selecting this suite without a database panics instead of silently passing.
//! Every test owns a random schema and real connections; there is no in-memory
//! fake, no Vault/object storage and no long-lived request transaction.
//!
//! These tests prove metadata row/lease behaviour only. They never claim a Git
//! object closure, pack membership, physical artifact hold, GC protection or
//! `git fsck` completeness: pack membership is typed `Unavailable` in A2.
use anyhow::{Context, Result};
use deadpool_postgres::{Manager, Pool};
use rootyard::db;
use rootyard::ref_store::{
    CommitMode, CommitRefsRequest, CoreGate, CoreGateInit, CoreGateVersion, CreateMetadataSnapshotOutcome,
    CreateMetadataSnapshotRequest, GitObjectFormat, GitOid, HeadUpdate, IssuerLane, MetadataMutationAction,
    MetadataPinOutcome, MetadataPinPurpose, MetadataReceipt, MetadataReceiptLookup, MetadataSnapshotPage,
    MetadataSnapshotScope, PgRefStoreCore, PinReleaseReason, REPO_MAX_SNAPSHOTS, ReadMetadataSnapshotPageRequest,
    RefName, RefPrecondition, RefPrefix, RefStoreError, RefTarget, RefUpdate, ReleaseMetadataPinRequest,
    RenewMetadataPinRequest, RequestDigest, VersionCheck,
};
use serde_json::json;
use std::time::Duration;
use tokio::sync::oneshot;
use tokio::time::Instant;
use uuid::Uuid;

const LEASE: i64 = 120;

/// Exact static reason from the backend's unserved-repository predicate.
const UNSERVED_TRANSITION_REASON: &str = "repository is no longer an explicitly unserved stable gitfs core repository";

fn database_url() -> String {
    std::env::var("ROOTYARD_TEST_DATABASE_URL")
        .expect("ROOTYARD_TEST_DATABASE_URL must be set when running the ignored ref_store_core_snapshot suite")
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(20)
}

fn lane() -> IssuerLane {
    IssuerLane::new("snapshot-test").unwrap()
}

fn oid(byte: u8) -> GitOid {
    GitOid::Sha1([byte; 20])
}

fn ref_name(value: &str) -> RefName {
    RefName::new(value).unwrap()
}

fn update(name: &str, old: Option<GitOid>, new: Option<GitOid>) -> RefUpdate {
    let precondition = match old {
        Some(old) => RefPrecondition::Present(old),
        None => RefPrecondition::Absent,
    };
    let target = match new {
        Some(new) => RefTarget::Oid(new),
        None => RefTarget::Delete,
    };
    RefUpdate::new(ref_name(name), precondition, target)
}

fn gate(repo: Uuid, tenant: Uuid, history: Uuid) -> CoreGateInit {
    CoreGateInit::new(repo, tenant, GitObjectFormat::Sha1, history, 1, 1, RefName::branch("refs/heads/main").unwrap())
        .unwrap()
}

#[allow(clippy::too_many_arguments)]
fn commit_request(
    repo: Uuid,
    tenant: Uuid,
    sequence: i64,
    operation: Uuid,
    history: Uuid,
    expected_revision: i64,
    refs: Vec<RefUpdate>,
) -> CommitRefsRequest {
    CommitRefsRequest::new(
        repo,
        tenant,
        tenant,
        lane(),
        sequence,
        operation,
        GitObjectFormat::Sha1,
        history,
        1,
        1,
        expected_revision,
        HeadUpdate::Keep,
        CommitMode::Atomic,
        refs,
    )
    .unwrap()
}

fn scope(repo: Uuid, tenant: Uuid, history: Uuid) -> MetadataSnapshotScope {
    MetadataSnapshotScope::new(
        repo,
        tenant,
        tenant,
        MetadataPinPurpose::Verification,
        GitObjectFormat::Sha1,
        history,
        1,
        1,
    )
    .unwrap()
}

async fn setup() -> Result<(Pool, Pool, String, Uuid, Uuid)> {
    let url = database_url();
    let admin = db::pool(&url)?;
    let schema = format!("ref_store_snapshot_test_{}", Uuid::new_v4().simple());
    admin.get().await?.batch_execute(&format!("CREATE SCHEMA {schema}")).await?;
    let mut config: tokio_postgres::Config = url.parse()?;
    config.options(format!("-c search_path={schema} -c timezone=UTC -c statement_timeout=15000 -c lock_timeout=10000"));
    let pool = Pool::builder(Manager::new(config, tokio_postgres::NoTls))
        .runtime(deadpool_postgres::Runtime::Tokio1)
        .max_size(16)
        .build()?;
    db::migrate(&pool).await?;
    let client = pool.get().await?;
    // The production migrator owns migration 140. This suite never applies a
    // root-reserved file itself, so a missing registration fails loudly instead
    // of silently fabricating DDL.
    let installed: bool = client
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=140)
                    AND to_regclass('ref_store_core_snapshots') IS NOT NULL",
            &[],
        )
        .await?
        .get(0);
    anyhow::ensure!(installed, "db::migrate did not install migration 140 (registration or snapshot table missing)");
    drop(client);
    let tenant = Uuid::new_v4();
    let repo = Uuid::new_v4();
    let client = pool.get().await?;
    client
        .execute(
            "INSERT INTO users(id,username) VALUES($1,$2)",
            &[&tenant, &format!("snap{}", &tenant.simple().to_string()[..12])],
        )
        .await?;
    client
        .execute(
            "INSERT INTO repositories(id,owner_id,name,state,object_format) VALUES($1,$2,'snapshot','provisioning','sha1')",
            &[&repo, &tenant],
        )
        .await?;
    drop(client);
    Ok((admin, pool, schema, tenant, repo))
}

async fn teardown(admin: &Pool, schema: &str) -> Result<()> {
    admin.get().await?.batch_execute(&format!("DROP SCHEMA {schema} CASCADE")).await?;
    Ok(())
}

/// Always attempt fixture cleanup, but never replace the test's original
/// failure with a secondary teardown error.
async fn finish(admin: &Pool, schema: &str, outcome: Result<()>) -> Result<()> {
    match outcome {
        Ok(()) => teardown(admin, schema).await,
        Err(error) => {
            let _ = teardown(admin, schema).await;
            Err(error)
        }
    }
}

fn pool_error(error: deadpool_postgres::PoolError) -> RefStoreError {
    RefStoreError::Database(error.to_string())
}

async fn initialize(pool: &Pool, init: &CoreGateInit) -> Result<CoreGate, RefStoreError> {
    let mut client = pool.get().await.map_err(pool_error)?;
    PgRefStoreCore.initialize(&mut client, init, deadline()).await
}

async fn initialize_and_seed(pool: &Pool, repo: Uuid, tenant: Uuid, history: Uuid) -> Result<()> {
    initialize(pool, &gate(repo, tenant, history)).await?;
    let mut client = pool.get().await?;
    let receipt = PgRefStoreCore
        .commit_refs(
            &mut client,
            &commit_request(
                repo,
                tenant,
                1,
                Uuid::new_v4(),
                history,
                1,
                vec![
                    update("refs/heads/main", None, Some(oid(1))),
                    update("refs/heads/feature/x", None, Some(oid(2))),
                    update("refs/tags/v1", None, Some(oid(3))),
                ],
            ),
            deadline(),
        )
        .await?;
    assert!(receipt.is_committed(), "seeding commit must commit");
    Ok(())
}

async fn gate_version(pool: &Pool, repo: Uuid, tenant: Uuid) -> Result<CoreGateVersion> {
    let mut client = pool.get().await?;
    match PgRefStoreCore.check_version(&mut client, repo, tenant, None, deadline()).await? {
        VersionCheck::Changed(version) | VersionCheck::Unchanged(version) => Ok(version),
        VersionCheck::Unknown => anyhow::bail!("seeded gate disappeared"),
    }
}

fn create_request(
    scope: MetadataSnapshotScope,
    gate_digest: &RequestDigest,
    lease: i64,
) -> (Uuid, CreateMetadataSnapshotRequest) {
    let request_id = Uuid::new_v4();
    let request =
        CreateMetadataSnapshotRequest::new(scope, request_id, Uuid::new_v4(), Uuid::new_v4(), lease, *gate_digest)
            .unwrap();
    (request_id, request)
}

async fn create(
    pool: &Pool,
    request: &CreateMetadataSnapshotRequest,
) -> Result<CreateMetadataSnapshotOutcome, RefStoreError> {
    let mut client = pool.get().await.map_err(pool_error)?;
    PgRefStoreCore.create_metadata_snapshot(&mut client, request, deadline()).await
}

async fn page(pool: &Pool, request: &ReadMetadataSnapshotPageRequest) -> Result<MetadataSnapshotPage, RefStoreError> {
    let mut client = pool.get().await.map_err(pool_error)?;
    PgRefStoreCore.read_metadata_snapshot_page(&mut client, request, deadline()).await
}

async fn renew(pool: &Pool, request: &RenewMetadataPinRequest) -> Result<MetadataPinOutcome, RefStoreError> {
    let mut client = pool.get().await.map_err(pool_error)?;
    PgRefStoreCore.renew_metadata_pin(&mut client, request, deadline()).await
}

async fn release(pool: &Pool, request: &ReleaseMetadataPinRequest) -> Result<MetadataPinOutcome, RefStoreError> {
    let mut client = pool.get().await.map_err(pool_error)?;
    PgRefStoreCore.release_metadata_pin(&mut client, request, deadline()).await
}

async fn lookup(
    pool: &Pool,
    scope: &MetadataSnapshotScope,
    request_id: Uuid,
) -> Result<MetadataReceiptLookup, RefStoreError> {
    let mut client = pool.get().await.map_err(pool_error)?;
    PgRefStoreCore.metadata_receipt(&mut client, scope, request_id, deadline()).await
}

async fn counts(pool: &Pool, repo: Uuid) -> Result<(i64, i64, i64, i64)> {
    let client = pool.get().await?;
    let row = client
        .query_one(
            "SELECT (SELECT count(*) FROM ref_store_core_snapshots WHERE repository_id=$1),
                    (SELECT count(*) FROM ref_store_core_snapshot_refs r
                        JOIN ref_store_core_snapshots s ON s.snapshot_id=r.snapshot_id
                     WHERE s.repository_id=$1),
                    (SELECT count(*) FROM ref_store_core_pins WHERE repository_id=$1),
                    (SELECT count(*) FROM ref_store_core_receipts WHERE repository_id=$1)",
            &[&repo],
        )
        .await?;
    Ok((row.get(0), row.get(1), row.get(2), row.get(3)))
}

async fn usage(pool: &Pool, repo: Uuid, tenant: Uuid) -> Result<(i64, i64, i64, i64, i64, i64, i64, i64)> {
    let client = pool.get().await?;
    // A rolled-back or never-started mutation leaves no usage row at all; that
    // is exactly zero retained usage, not a missing observation.
    let counters = |row: Option<tokio_postgres::Row>| -> (i64, i64, i64, i64) {
        match row {
            Some(row) => (row.get(0), row.get(1), row.get(2), row.get(3)),
            None => (0, 0, 0, 0),
        }
    };
    let repo_row = counters(
        client
            .query_opt(
                "SELECT snapshot_count,snapshot_ref_count,logical_bytes,receipt_count
                 FROM ref_store_core_repo_usage WHERE repository_id=$1",
                &[&repo],
            )
            .await?,
    );
    let tenant_row = counters(
        client
            .query_opt(
                "SELECT snapshot_count,snapshot_ref_count,logical_bytes,receipt_count
                 FROM ref_store_core_tenant_usage WHERE tenant_id=$1",
                &[&tenant],
            )
            .await?,
    );
    Ok((repo_row.0, repo_row.1, repo_row.2, repo_row.3, tenant_row.0, tenant_row.1, tenant_row.2, tenant_row.3))
}

/// Fixture-owned deferred barrier: a receipt insert is valid, but `COMMIT`
/// waits on an advisory lock held by another fixture connection. Only this
/// fixture owns the function, trigger and key.
async fn install_receipt_barrier(pool: &Pool, key: i64) -> Result<()> {
    pool.get()
        .await?
        .batch_execute(&format!(
            "CREATE FUNCTION snapshot_receipt_barrier() RETURNS trigger LANGUAGE plpgsql AS $$
               BEGIN PERFORM pg_advisory_xact_lock({key}); RETURN NEW; END $$;
             CREATE CONSTRAINT TRIGGER snapshot_receipt_barrier AFTER INSERT ON ref_store_core_receipts
               DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION snapshot_receipt_barrier();"
        ))
        .await?;
    Ok(())
}

async fn drop_receipt_barrier(pool: &Pool) -> Result<()> {
    pool.get()
        .await?
        .batch_execute(
            "DROP TRIGGER snapshot_receipt_barrier ON ref_store_core_receipts;
             DROP FUNCTION snapshot_receipt_barrier();",
        )
        .await?;
    Ok(())
}

/// Fixture-owned statement-level barrier for the renewal `UPDATE`. It fires
/// before row/`WHERE` evaluation, so it parks the statement after the adapter's
/// live pin check but before the backend expiry predicate is evaluated. A row
/// trigger would fire after `WHERE` and could not prove that interleaving.
async fn install_renew_update_barrier(pool: &Pool, key: i64) -> Result<()> {
    pool.get()
        .await?
        .batch_execute(&format!(
            "CREATE FUNCTION snapshot_renew_park() RETURNS trigger LANGUAGE plpgsql AS $$
               BEGIN PERFORM pg_advisory_xact_lock({key}); RETURN NULL; END $$;
             CREATE TRIGGER snapshot_renew_park BEFORE UPDATE ON ref_store_core_pins
               FOR EACH STATEMENT EXECUTE FUNCTION snapshot_renew_park();"
        ))
        .await?;
    Ok(())
}

async fn drop_renew_update_barrier(pool: &Pool) -> Result<()> {
    pool.get()
        .await?
        .batch_execute(
            "DROP TRIGGER snapshot_renew_park ON ref_store_core_pins;
             DROP FUNCTION snapshot_renew_park();",
        )
        .await?;
    Ok(())
}

/// Owned fixture barrier. The session-level advisory lock is released by an
/// owned task; dropping the sender (including on an early error) also releases
/// it, and the client closes with the task, so no barrier is stranded.
struct Barrier {
    release: Option<oneshot::Sender<()>>,
    unlock: Option<tokio::task::JoinHandle<()>>,
}

impl Barrier {
    async fn release(mut self) -> Result<()> {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
        if let Some(unlock) = self.unlock.take() {
            unlock.await.context("fixture barrier unlock task failed")?;
        }
        Ok(())
    }
}

impl Drop for Barrier {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
    }
}

async fn acquire_barrier(pool: &Pool, key: i64) -> Result<Barrier> {
    let client = pool.get().await?;
    client.query_one("SELECT pg_advisory_lock($1)", &[&key]).await?;
    let (release, released) = oneshot::channel::<()>();
    let unlock = tokio::spawn(async move {
        let _ = released.await;
        let _ = client.query_one("SELECT pg_advisory_unlock($1)", &[&key]).await;
    });
    Ok(Barrier { release: Some(release), unlock: Some(unlock) })
}

async fn wait_for_advisory_wait(pool: &Pool, pid: i32) -> Result<()> {
    let observer = pool.get().await?;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let waiting: bool = observer
                .query_one(
                    "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='advisory' AND NOT granted)",
                    &[&pid],
                )
                .await?
                .get(0);
            if waiting {
                return Ok::<(), anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .context("backend never blocked on the fixture advisory barrier")??;
    Ok(())
}

/// Deterministic PG observer: the commit backend itself must be reported by
/// `pg_stat_activity` as active and waiting on the core gate row lock, while
/// its current statement is the gate query. An unscheduled or sleeping task
/// cannot satisfy this.
async fn wait_for_commit_gate_lock(pool: &Pool, pid: i32) -> Result<()> {
    let observer = pool.get().await?;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let blocked: bool = observer
                .query_one(
                    "SELECT EXISTS(SELECT 1 FROM pg_stat_activity
                       WHERE pid=$1 AND state='active' AND wait_event_type='Lock'
                         AND query LIKE '%ref_store_core_gates%')",
                    &[&pid],
                )
                .await?
                .get(0);
            if blocked {
                return Ok::<(), anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .context("CommitRefs backend never blocked on the core gate row lock")??;
    Ok(())
}

/// Bounded database-clock observer: wait for the server to pass the stored
/// lease expiry instead of sleeping for a guessed client duration.
async fn wait_past_pin_expiry(pool: &Pool, pin_id: Uuid) -> Result<()> {
    let observer = pool.get().await?;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let expired: bool = observer
                .query_one(
                    "SELECT expires_at <= clock_timestamp() FROM ref_store_core_pins WHERE pin_id=$1",
                    &[&pin_id],
                )
                .await?
                .get(0);
            if expired {
                return Ok::<(), anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .context("postgres clock never passed the pin expiry")??;
    Ok(())
}

async fn pin_status(pool: &Pool, pin_id: Uuid) -> Result<(String, i64, i64)> {
    let row = pool
        .get()
        .await?
        .query_one(
            "SELECT state,generation,(extract(epoch FROM expires_at)*1000000)::bigint
             FROM ref_store_core_pins WHERE pin_id=$1",
            &[&pin_id],
        )
        .await?;
    Ok((row.get(0), row.get(1), row.get(2)))
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn capture_serializes_with_commit_refs_and_commits_one_revision() -> Result<()> {
    let (admin, pool, schema, tenant, repo) = setup().await?;
    let outcome = async {
        let history = Uuid::new_v4();
        initialize_and_seed(&pool, repo, tenant, history).await?;
        let before = gate_version(&pool, repo, tenant).await?;
        let before_revision = before.revision();
        assert_eq!(before_revision, 2);
        let (_, request) = create_request(scope(repo, tenant, history), before.digest(), LEASE);

        let key = i64::from_be_bytes(Uuid::new_v4().into_bytes()[..8].try_into().expect("eight bytes"));
        let barrier = acquire_barrier(&pool, key).await?;
        install_receipt_barrier(&pool, key).await?;

        let mut create_client = pool.get().await?;
        let create_pid: i32 = create_client.query_one("SELECT pg_backend_pid()", &[]).await?.get(0);
        let (release_tx, release_rx) = oneshot::channel::<()>();
        let create_task = tokio::spawn(async move {
            let outcome = PgRefStoreCore
                .create_metadata_snapshot(&mut create_client, &request, Instant::now() + Duration::from_secs(30))
                .await;
            let _ = release_rx.await;
            let _ = create_client.batch_execute("SELECT 1").await;
            outcome
        });
        wait_for_advisory_wait(&pool, create_pid).await?;

        // A concurrent commit must wait for the gate row lock capture holds.
        // The commit backend itself is observed in `pg_stat_activity` inside the
        // gate statement; an unscheduled or sleeping task cannot pass this.
        let mut commit_client = pool.get().await?;
        let commit_pid: i32 = commit_client.query_one("SELECT pg_backend_pid()", &[]).await?.get(0);
        let (commit_started_tx, commit_started_rx) = oneshot::channel::<()>();
        let commit = tokio::spawn(async move {
            let _ = commit_started_tx.send(());
            PgRefStoreCore
                .commit_refs(
                    &mut commit_client,
                    &commit_request(
                        repo,
                        tenant,
                        2,
                        Uuid::new_v4(),
                        history,
                        before_revision,
                        vec![update("refs/heads/main", Some(oid(1)), Some(oid(4)))],
                    ),
                    Instant::now() + Duration::from_secs(10),
                )
                .await
        });
        tokio::time::timeout(Duration::from_secs(10), commit_started_rx)
            .await
            .context("commit task never signalled its start")??;
        wait_for_commit_gate_lock(&pool, commit_pid).await?;
        assert!(!commit.is_finished(), "CommitRefs escaped the gate lock held by capture");

        barrier.release().await?;
        let _ = release_tx.send(());
        let created = tokio::time::timeout(Duration::from_secs(10), create_task)
            .await
            .context("capture did not settle after barrier release")???;
        assert!(!created.replayed);
        assert_eq!(created.receipt.gate_revision(), before_revision);
        assert_eq!(created.receipt.ref_count(), 3);
        assert_eq!(created.receipt.head_ref(), "refs/heads/main");
        assert_eq!(created.receipt.head_oid_hex(), Some(oid(1).as_hex().as_str()));

        let committed = tokio::time::timeout(Duration::from_secs(10), commit)
            .await
            .context("CommitRefs did not settle after capture")???;
        assert!(committed.is_committed());

        // A later capture observes the newer revision and refs.
        let after = gate_version(&pool, repo, tenant).await?;
        assert_eq!(after.revision(), 3);
        let (_, second) = create_request(scope(repo, tenant, history), after.digest(), LEASE);
        let second = create(&pool, &second).await?;
        assert_eq!(second.receipt.gate_revision(), 3);
        assert_eq!(second.receipt.head_oid_hex(), Some(oid(4).as_hex().as_str()));
        assert_eq!(counts(&pool, repo).await?, (2, 6, 2, 2));
        assert!(!second.receipt.complete_git_read_snapshot());
        assert!(!second.receipt.packs().complete_git_read_snapshot());
        drop_receipt_barrier(&pool).await?;
        Ok::<(), anyhow::Error>(())
    }
    .await;
    finish(&admin, &schema, outcome).await
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn stale_gate_is_rejected_and_pages_stay_immutable_while_refs_change() -> Result<()> {
    let (admin, pool, schema, tenant, repo) = setup().await?;
    let outcome = async {
        let history = Uuid::new_v4();
        initialize_and_seed(&pool, repo, tenant, history).await?;
        let v2 = gate_version(&pool, repo, tenant).await?;
        let (_, created) = create_request(scope(repo, tenant, history), v2.digest(), LEASE);
        let receipt = create(&pool, &created).await?.receipt;

        let mut client = pool.get().await?;
        let committed = PgRefStoreCore
            .commit_refs(
                &mut client,
                &commit_request(
                    repo,
                    tenant,
                    2,
                    Uuid::new_v4(),
                    history,
                    v2.revision(),
                    vec![
                        update("refs/heads/main", Some(oid(1)), Some(oid(5))),
                        update("refs/tags/v1", Some(oid(3)), None),
                    ],
                ),
                deadline(),
            )
            .await?;
        assert!(committed.is_committed());

        let (_, stale) = create_request(scope(repo, tenant, history), v2.digest(), LEASE);
        match create(&pool, &stale).await {
            Err(RefStoreError::MetadataGateVersionMismatch) => {}
            other => panic!("stale gate proof must be a typed rejection: {other:?}"),
        }
        assert_eq!(counts(&pool, repo).await?, (1, 3, 1, 1), "stale capture wrote rows");

        let mut request = ReadMetadataSnapshotPageRequest::new(
            scope(repo, tenant, history),
            receipt.snapshot_id(),
            receipt.pin_id(),
            1,
            None,
            None,
            2,
        )?;
        let first = page(&pool, &request).await?;
        assert_eq!(first.gate_revision(), v2.revision());
        assert_eq!(first.ref_count(), 3);
        assert_eq!(first.refs().len(), 2);
        assert_eq!(first.refs()[0].name().as_str(), "refs/heads/feature/x");
        assert_eq!(first.refs()[0].oid(), oid(2));
        assert_eq!(first.refs()[1].name().as_str(), "refs/heads/main");
        assert_eq!(
            first.refs()[1].oid(),
            oid(1),
            "pages must keep the captured OID for a same-named ref, not the later revision"
        );
        assert!(!first.complete());
        let cursor = first.next().cloned().expect("cursor");
        request = ReadMetadataSnapshotPageRequest::new(
            scope(repo, tenant, history),
            receipt.snapshot_id(),
            receipt.pin_id(),
            1,
            None,
            Some(cursor),
            2,
        )?;
        let second = page(&pool, &request).await?;
        assert_eq!(second.refs().len(), 1);
        assert_eq!(second.refs()[0].name().as_str(), "refs/tags/v1");
        assert_eq!(second.refs()[0].oid(), oid(3));
        assert!(second.complete());

        let prefixed = ReadMetadataSnapshotPageRequest::new(
            scope(repo, tenant, history),
            receipt.snapshot_id(),
            receipt.pin_id(),
            1,
            Some(RefPrefix::new("refs/heads/")?),
            None,
            256,
        )?;
        let prefixed = page(&pool, &prefixed).await?;
        assert_eq!(prefixed.refs().len(), 2);
        assert!(prefixed.complete());
        Ok::<(), anyhow::Error>(())
    }
    .await;
    finish(&admin, &schema, outcome).await
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn exact_create_replay_returns_old_receipt_and_never_double_charges() -> Result<()> {
    let (admin, pool, schema, tenant, repo) = setup().await?;
    let outcome = async {
        let history = Uuid::new_v4();
        initialize_and_seed(&pool, repo, tenant, history).await?;
        let version = gate_version(&pool, repo, tenant).await?;
        let (request_id, request) = create_request(scope(repo, tenant, history), version.digest(), LEASE);
        let first = create(&pool, &request).await?;
        let charged = usage(&pool, repo, tenant).await?;
        assert_eq!((charged.0, charged.1, charged.3), (1, 3, 1));
        assert!(charged.2 > 0);
        assert_eq!(charged.0, charged.4, "tenant usage mirrors the repository usage");

        let replay = create(&pool, &request).await?;
        assert!(replay.replayed);
        assert_eq!(replay.receipt, first.receipt, "replay must return the original immutable receipt");
        assert_eq!(usage(&pool, repo, tenant).await?, charged, "replay must not double-charge");
        assert_eq!(counts(&pool, repo).await?, (1, 3, 1, 1));

        let conflicting = CreateMetadataSnapshotRequest::new(
            scope(repo, tenant, history),
            request_id,
            request.pin_id(),
            request.snapshot_id(),
            LEASE + 1,
            *version.digest(),
        )?;
        match create(&pool, &conflicting).await {
            Err(RefStoreError::DigestConflict) => {}
            other => panic!("different digest must conflict: {other:?}"),
        }
        assert_eq!(usage(&pool, repo, tenant).await?, charged);

        match lookup(&pool, &scope(repo, tenant, history), request_id).await? {
            MetadataReceiptLookup::Found(MetadataReceipt::Snapshot(found)) => assert_eq!(found, first.receipt),
            other => panic!("create receipt lookup failed: {other:?}"),
        }
        Ok::<(), anyhow::Error>(())
    }
    .await;
    finish(&admin, &schema, outcome).await
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn failure_after_inserts_rolls_back_every_metadata_row() -> Result<()> {
    let (admin, pool, schema, tenant, repo) = setup().await?;
    let outcome = async {
        let history = Uuid::new_v4();
        initialize_and_seed(&pool, repo, tenant, history).await?;
        let version = gate_version(&pool, repo, tenant).await?;
        pool.get()
            .await?
            .batch_execute(
                "CREATE FUNCTION snapshot_fail_receipt() RETURNS trigger LANGUAGE plpgsql AS $$
                   BEGIN RAISE EXCEPTION 'fixture receipt failure'; END $$;
                 CREATE TRIGGER snapshot_fail_receipt BEFORE INSERT ON ref_store_core_receipts
                   FOR EACH ROW EXECUTE FUNCTION snapshot_fail_receipt();",
            )
            .await?;
        let (_, request) = create_request(scope(repo, tenant, history), version.digest(), LEASE);
        let result = create(&pool, &request).await;
        assert!(matches!(result, Err(RefStoreError::Database(_))), "unexpected {result:?}");
        assert_eq!(counts(&pool, repo).await?, (0, 0, 0, 0));
        assert_eq!(usage(&pool, repo, tenant).await?, (0, 0, 0, 0, 0, 0, 0, 0), "usage must roll back");
        pool.get()
            .await?
            .batch_execute(
                "DROP TRIGGER snapshot_fail_receipt ON ref_store_core_receipts;
                 DROP FUNCTION snapshot_fail_receipt();",
            )
            .await?;
        let created = create(&pool, &request).await?;
        assert!(!created.replayed);
        assert_eq!(counts(&pool, repo).await?, (1, 3, 1, 1));
        Ok::<(), anyhow::Error>(())
    }
    .await;
    finish(&admin, &schema, outcome).await
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn unknown_commit_resolves_by_same_request_id() -> Result<()> {
    let (admin, pool, schema, tenant, repo) = setup().await?;
    let outcome = async {
        let history = Uuid::new_v4();
        initialize_and_seed(&pool, repo, tenant, history).await?;
        let version = gate_version(&pool, repo, tenant).await?;
        let (request_id, request) = create_request(scope(repo, tenant, history), version.digest(), LEASE);
        let pin_id = request.pin_id();
        let retry = request.clone();

        let key = i64::from_be_bytes(Uuid::new_v4().into_bytes()[..8].try_into().expect("eight bytes"));
        let barrier = acquire_barrier(&pool, key).await?;
        install_receipt_barrier(&pool, key).await?;

        let mut client = pool.get().await?;
        let pid: i32 = client.query_one("SELECT pg_backend_pid()", &[]).await?.get(0);
        let (release_tx, release_rx) = oneshot::channel::<()>();
        let (returned_tx, returned_rx) = oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            let result = PgRefStoreCore
                .create_metadata_snapshot(&mut client, &request, Instant::now() + Duration::from_millis(2000))
                .await;
            let _ = returned_tx.send(());
            let _ = release_rx.await;
            client.batch_execute("SELECT 1").await.expect("queued statement must settle on the borrowed client");
            result
        });
        wait_for_advisory_wait(&pool, pid).await?;
        tokio::time::timeout(Duration::from_secs(10), returned_rx)
            .await
            .context("create never returned at its deadline")??;
        barrier.release().await?;
        let _ = release_tx.send(());
        let result =
            tokio::time::timeout(Duration::from_secs(10), task).await.context("create task did not settle")??;
        match result {
            Err(RefStoreError::MetadataCommitUnknown {
                repository_id,
                request_id: unknown,
                pin_id: unknown_pin,
                action,
            }) => {
                assert_eq!(repository_id, repo);
                assert_eq!(unknown, request_id);
                assert_eq!(unknown_pin, pin_id);
                assert_eq!(action, MetadataMutationAction::Create);
            }
            other => panic!("COMMIT at its deadline must be typed metadata unknown: {other:?}"),
        }
        drop_receipt_barrier(&pool).await?;

        // The ledger resolves the same id as Found or Unknown, never as a
        // claimed abort; the exact retry converges to exactly one grant.
        let resolved = lookup(&pool, &scope(repo, tenant, history), request_id).await?;
        let retried = create(&pool, &retry).await?;
        assert_eq!(retried.receipt.pin_id(), pin_id);
        assert_eq!(counts(&pool, repo).await?, (1, 3, 1, 1), "unknown commit duplicated metadata");
        assert_eq!(usage(&pool, repo, tenant).await?.0, 1, "usage charged exactly once");
        match (resolved, retried.replayed) {
            (MetadataReceiptLookup::Found(MetadataReceipt::Snapshot(found)), true) => {
                assert_eq!(found, retried.receipt)
            }
            (MetadataReceiptLookup::Unknown, false) => {}
            (resolved, replayed) => panic!("unexpected resolution/replay pair: {resolved:?} {replayed}"),
        }
        Ok::<(), anyhow::Error>(())
    }
    .await;
    finish(&admin, &schema, outcome).await
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn renew_release_generation_aba_and_exact_replay() -> Result<()> {
    let (admin, pool, schema, tenant, repo) = setup().await?;
    let outcome = async {
        let history = Uuid::new_v4();
        initialize_and_seed(&pool, repo, tenant, history).await?;
        let version = gate_version(&pool, repo, tenant).await?;
        let (_, request) = create_request(scope(repo, tenant, history), version.digest(), 60);
        let created = create(&pool, &request).await?;
        let pin_id = created.receipt.pin_id();
        let snapshot_id = created.receipt.snapshot_id();

        // Renew advances exactly one generation and returns a fresh receipt.
        let renew_request = RenewMetadataPinRequest::new(scope(repo, tenant, history), Uuid::new_v4(), pin_id, 1, 60)?;
        let first = renew(&pool, &renew_request).await?;
        assert!(!first.replayed);
        assert_eq!(first.receipt.pin_generation(), 2);
        assert_eq!(first.receipt.snapshot_id(), snapshot_id);
        let replay = renew(&pool, &renew_request).await?;
        assert!(replay.replayed);
        assert_eq!(replay.receipt, first.receipt);

        // A stale generation never renews and never releases a newer pin.
        match renew(&pool, &RenewMetadataPinRequest::new(scope(repo, tenant, history), Uuid::new_v4(), pin_id, 1, 60)?)
            .await
        {
            Err(RefStoreError::MetadataPinGenerationMismatch { expected, actual, .. }) => {
                assert_eq!((expected, actual), (1, 2));
            }
            other => panic!("stale renew must mismatch: {other:?}"),
        }
        match release(
            &pool,
            &ReleaseMetadataPinRequest::new(
                scope(repo, tenant, history),
                Uuid::new_v4(),
                pin_id,
                1,
                PinReleaseReason::Superseded,
            )?,
        )
        .await
        {
            Err(RefStoreError::MetadataPinGenerationMismatch { .. }) => {}
            other => panic!("old-generation release must not end a newer pin: {other:?}"),
        }

        // The exact current generation releases once, with an immutable receipt.
        let release_request = ReleaseMetadataPinRequest::new(
            scope(repo, tenant, history),
            Uuid::new_v4(),
            pin_id,
            2,
            PinReleaseReason::ClientDone,
        )?;
        let released = release(&pool, &release_request).await?;
        assert!(!released.replayed);
        assert_eq!(released.receipt.action(), MetadataMutationAction::Release);
        assert_eq!(released.receipt.pin_generation(), 2);
        assert!(released.receipt.released_at_unix_micros().is_some());
        assert_eq!(released.receipt.release_reason(), Some(PinReleaseReason::ClientDone));
        let released_replay = release(&pool, &release_request).await?;
        assert!(released_replay.replayed);
        assert_eq!(released_replay.receipt, released.receipt);

        // A released pin is terminal: no page, no renew, no second release.
        let page_request =
            ReadMetadataSnapshotPageRequest::new(scope(repo, tenant, history), snapshot_id, pin_id, 2, None, None, 16)?;
        assert!(matches!(page(&pool, &page_request).await, Err(RefStoreError::MetadataPinReleased { .. })));
        assert!(matches!(
            renew(&pool, &RenewMetadataPinRequest::new(scope(repo, tenant, history), Uuid::new_v4(), pin_id, 2, 60)?)
                .await,
            Err(RefStoreError::MetadataPinReleased { .. })
        ));
        assert!(matches!(
            release(
                &pool,
                &ReleaseMetadataPinRequest::new(
                    scope(repo, tenant, history),
                    Uuid::new_v4(),
                    pin_id,
                    2,
                    PinReleaseReason::MaintenanceComplete,
                )?
            )
            .await,
            Err(RefStoreError::MetadataPinReleased { .. })
        ));

        // Release never refunds retained admission usage.
        let counters = usage(&pool, repo, tenant).await?;
        assert_eq!(counters.0, 1, "released snapshot stays retained");
        assert_eq!(counters.1, 3, "released snapshot refs stay retained");
        assert_eq!(counters.3, 3, "create + one renew + one release receipt are charged once each");
        assert_eq!(counts(&pool, repo).await?, (1, 3, 1, 3), "replays add no receipt row");
        Ok::<(), anyhow::Error>(())
    }
    .await;
    finish(&admin, &schema, outcome).await
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn expired_pin_denies_pages_and_renew_but_release_is_exact() -> Result<()> {
    let (admin, pool, schema, tenant, repo) = setup().await?;
    let outcome = async {
        let history = Uuid::new_v4();
        initialize_and_seed(&pool, repo, tenant, history).await?;
        let version = gate_version(&pool, repo, tenant).await?;
        let (_, request) = create_request(scope(repo, tenant, history), version.digest(), 1);
        let created = create(&pool, &request).await?;
        let pin_id = created.receipt.pin_id();
        let snapshot_id = created.receipt.snapshot_id();
        wait_past_pin_expiry(&pool, pin_id).await?;

        let page_request =
            ReadMetadataSnapshotPageRequest::new(scope(repo, tenant, history), snapshot_id, pin_id, 1, None, None, 16)?;
        assert!(matches!(page(&pool, &page_request).await, Err(RefStoreError::MetadataPinExpired { .. })));
        assert!(matches!(
            renew(&pool, &RenewMetadataPinRequest::new(scope(repo, tenant, history), Uuid::new_v4(), pin_id, 1, 60)?)
                .await,
            Err(RefStoreError::MetadataPinExpired { .. })
        ));

        // Expiry keeps the rows and the usage; only an exact release is terminal.
        assert_eq!(counts(&pool, repo).await?, (1, 3, 1, 1));
        let released = release(
            &pool,
            &ReleaseMetadataPinRequest::new(
                scope(repo, tenant, history),
                Uuid::new_v4(),
                pin_id,
                1,
                PinReleaseReason::LeaseAbandoned,
            )?,
        )
        .await?;
        assert_eq!(released.receipt.pin_generation(), 1);
        let counters = usage(&pool, repo, tenant).await?;
        assert_eq!((counters.0, counters.1), (1, 3), "release must not delete or refund");
        assert_eq!(counters.3, 2);
        let state: String = pool
            .get()
            .await?
            .query_one("SELECT state FROM ref_store_core_pins WHERE pin_id=$1", &[&pin_id])
            .await?
            .get(0);
        assert_eq!(state, "released");
        Ok::<(), anyhow::Error>(())
    }
    .await;
    finish(&admin, &schema, outcome).await
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn transition_blocks_pages_and_renew_but_allows_exact_release() -> Result<()> {
    let (admin, pool, schema, tenant, repo) = setup().await?;
    let outcome = async {
        let history = Uuid::new_v4();
        initialize_and_seed(&pool, repo, tenant, history).await?;
        let version = gate_version(&pool, repo, tenant).await?;
        let (_, request) = create_request(scope(repo, tenant, history), version.digest(), LEASE);
        let created = create(&pool, &request).await?;
        let pin_id = created.receipt.pin_id();
        let snapshot_id = created.receipt.snapshot_id();
        pool.get()
            .await?
            .execute(
                "UPDATE repositories SET transition_state='draining',transition_id=$2,
                    transition_started_at=clock_timestamp() WHERE id=$1",
                &[&repo, &Uuid::new_v4()],
            )
            .await?;

        let page_request =
            ReadMetadataSnapshotPageRequest::new(scope(repo, tenant, history), snapshot_id, pin_id, 1, None, None, 16)?;
        match page(&pool, &page_request).await {
            Err(RefStoreError::Unsupported(reason)) => assert_eq!(reason, UNSERVED_TRANSITION_REASON),
            other => panic!("transition must deny pages with the exact unserved reason: {other:?}"),
        }
        match renew(&pool, &RenewMetadataPinRequest::new(scope(repo, tenant, history), Uuid::new_v4(), pin_id, 1, 60)?)
            .await
        {
            Err(RefStoreError::Unsupported(reason)) => assert_eq!(reason, UNSERVED_TRANSITION_REASON),
            other => panic!("transition must deny renew with the exact unserved reason: {other:?}"),
        }
        let (_, blocked) = create_request(scope(repo, tenant, history), version.digest(), LEASE);
        match create(&pool, &blocked).await {
            Err(RefStoreError::Unsupported(reason)) => assert_eq!(reason, UNSERVED_TRANSITION_REASON),
            other => panic!("transition must deny capture with the exact unserved reason: {other:?}"),
        }

        let released = release(
            &pool,
            &ReleaseMetadataPinRequest::new(
                scope(repo, tenant, history),
                Uuid::new_v4(),
                pin_id,
                1,
                PinReleaseReason::OperatorRequest,
            )?,
        )
        .await?;
        assert_eq!(released.receipt.pin_generation(), 1);
        assert_eq!(counts(&pool, repo).await?, (1, 3, 1, 2));
        Ok::<(), anyhow::Error>(())
    }
    .await;
    finish(&admin, &schema, outcome).await
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn scope_and_cursor_fences() -> Result<()> {
    let (admin, pool, schema, tenant, repo) = setup().await?;
    let outcome = async {
        let history = Uuid::new_v4();
        initialize_and_seed(&pool, repo, tenant, history).await?;
        let version = gate_version(&pool, repo, tenant).await?;
        let (_, first) = create_request(scope(repo, tenant, history), version.digest(), LEASE);
        let first = create(&pool, &first).await?.receipt;
        let (_, second) = create_request(scope(repo, tenant, history), version.digest(), LEASE);
        let second = create(&pool, &second).await?.receipt;

        let cursor = {
            let request = ReadMetadataSnapshotPageRequest::new(
                scope(repo, tenant, history),
                first.snapshot_id(),
                first.pin_id(),
                1,
                None,
                None,
                2,
            )?;
            page(&pool, &request).await?.next().cloned().expect("first page yields a cursor")
        };

        let wrong_tenant = MetadataSnapshotScope::new(
            repo,
            Uuid::new_v4(),
            tenant,
            MetadataPinPurpose::Verification,
            GitObjectFormat::Sha1,
            history,
            1,
            1,
        )?;
        assert!(matches!(
            page(
                &pool,
                &ReadMetadataSnapshotPageRequest::new(
                    wrong_tenant,
                    first.snapshot_id(),
                    first.pin_id(),
                    1,
                    None,
                    None,
                    8
                )?
            )
            .await,
            Err(RefStoreError::RepositoryNotFound)
        ));
        let wrong_owner = MetadataSnapshotScope::new(
            repo,
            tenant,
            Uuid::new_v4(),
            MetadataPinPurpose::Verification,
            GitObjectFormat::Sha1,
            history,
            1,
            1,
        )?;
        assert!(matches!(
            page(
                &pool,
                &ReadMetadataSnapshotPageRequest::new(
                    wrong_owner,
                    first.snapshot_id(),
                    first.pin_id(),
                    1,
                    None,
                    None,
                    8
                )?
            )
            .await,
            Err(RefStoreError::MetadataScopeMismatch(_))
        ));
        for wrong in [
            MetadataSnapshotScope::new(
                repo,
                tenant,
                tenant,
                MetadataPinPurpose::Backup,
                GitObjectFormat::Sha1,
                history,
                1,
                1,
            )?,
            MetadataSnapshotScope::new(
                repo,
                tenant,
                tenant,
                MetadataPinPurpose::Verification,
                GitObjectFormat::Sha1,
                history,
                2,
                1,
            )?,
            MetadataSnapshotScope::new(
                repo,
                tenant,
                tenant,
                MetadataPinPurpose::Verification,
                GitObjectFormat::Sha1,
                history,
                1,
                2,
            )?,
            MetadataSnapshotScope::new(
                repo,
                tenant,
                tenant,
                MetadataPinPurpose::Verification,
                GitObjectFormat::Sha256,
                history,
                1,
                1,
            )?,
        ] {
            assert!(matches!(
                page(
                    &pool,
                    &ReadMetadataSnapshotPageRequest::new(
                        wrong,
                        first.snapshot_id(),
                        first.pin_id(),
                        1,
                        None,
                        None,
                        8
                    )?
                )
                .await,
                Err(RefStoreError::MetadataScopeMismatch(_))
            ));
        }

        // History incarnation is part of the live gate scope for new pages and
        // renewals, not only of the immutable snapshot header.
        let wrong_history = MetadataSnapshotScope::new(
            repo,
            tenant,
            tenant,
            MetadataPinPurpose::Verification,
            GitObjectFormat::Sha1,
            Uuid::new_v4(),
            1,
            1,
        )?;
        match page(
            &pool,
            &ReadMetadataSnapshotPageRequest::new(
                wrong_history,
                first.snapshot_id(),
                first.pin_id(),
                1,
                None,
                None,
                8,
            )?,
        )
        .await
        {
            Err(RefStoreError::MetadataScopeMismatch(reason)) => {
                assert_eq!(reason, "gate history incarnation")
            }
            other => panic!("history incarnation must fence pages: {other:?}"),
        }
        match renew(&pool, &RenewMetadataPinRequest::new(wrong_history, Uuid::new_v4(), first.pin_id(), 1, 60)?).await {
            Err(RefStoreError::MetadataScopeMismatch(reason)) => {
                assert_eq!(reason, "gate history incarnation")
            }
            other => panic!("history incarnation must fence renewals: {other:?}"),
        }

        // A cursor is bound to its snapshot/pin/generation/prefix/scope.
        assert!(matches!(
            ReadMetadataSnapshotPageRequest::new(
                scope(repo, tenant, history),
                second.snapshot_id(),
                second.pin_id(),
                1,
                None,
                Some(cursor.clone()),
                8
            ),
            Err(RefStoreError::MetadataCursorScopeMismatch)
        ));
        assert!(matches!(
            ReadMetadataSnapshotPageRequest::new(
                scope(repo, tenant, history),
                first.snapshot_id(),
                first.pin_id(),
                1,
                Some(RefPrefix::new("refs/heads/")?),
                Some(cursor.clone()),
                8
            ),
            Err(RefStoreError::MetadataCursorScopeMismatch)
        ));

        // Renewal moves the generation; a stale page is a typed mismatch.
        renew(
            &pool,
            &RenewMetadataPinRequest::new(scope(repo, tenant, history), Uuid::new_v4(), first.pin_id(), 1, 60)?,
        )
        .await?;
        assert!(matches!(
            page(
                &pool,
                &ReadMetadataSnapshotPageRequest::new(
                    scope(repo, tenant, history),
                    first.snapshot_id(),
                    first.pin_id(),
                    1,
                    None,
                    None,
                    8
                )?
            )
            .await,
            Err(RefStoreError::MetadataPinGenerationMismatch { expected: 1, actual: 2, .. })
        ));
        assert!(matches!(
            ReadMetadataSnapshotPageRequest::new(
                scope(repo, tenant, history),
                first.snapshot_id(),
                first.pin_id(),
                2,
                None,
                Some(cursor),
                8
            ),
            Err(RefStoreError::MetadataCursorScopeMismatch)
        ));
        Ok::<(), anyhow::Error>(())
    }
    .await;
    finish(&admin, &schema, outcome).await
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn retained_quota_is_exact_without_refund_and_racing_creates() -> Result<()> {
    let (admin, pool, schema, tenant, repo) = setup().await?;
    let outcome = async {
        let history = Uuid::new_v4();
        initialize_and_seed(&pool, repo, tenant, history).await?;
        let version = gate_version(&pool, repo, tenant).await?;
        // Fixture seeding of retained history: REPO_MAX_SNAPSHOTS - 1 snapshots
        // with matching usage counters. This does not imitate a capture path.
        let seeded = REPO_MAX_SNAPSHOTS - 1;
        let ids = (0..seeded).map(|_| Uuid::new_v4()).collect::<Vec<_>>();
        let client = pool.get().await?;
        client
            .execute(
                "INSERT INTO ref_store_core_snapshots(
                     snapshot_id,repository_id,tenant_id,owner_id,purpose,object_format,history_incarnation,
                     authority_epoch,group_epoch,gate_revision,gate_digest,head_ref,head_oid,ref_count,
                     refs_digest,logical_bytes)
                 SELECT id,$1,$2,$2,'verification','sha1',$3,1,1,$4,$5,'refs/heads/main',NULL,0,$5,1
                 FROM unnest($6::uuid[]) AS id",
                &[&repo, &tenant, &history, &2_i64, &"a".repeat(64), &ids],
            )
            .await?;
        client
            .execute(
                "INSERT INTO ref_store_core_repo_usage(repository_id,tenant_id,snapshot_count,logical_bytes)
                 VALUES($1,$2,$3,$3) ON CONFLICT(repository_id) DO UPDATE
                 SET snapshot_count=$3,logical_bytes=$3",
                &[&repo, &tenant, &seeded],
            )
            .await?;
        client
            .execute(
                "INSERT INTO ref_store_core_tenant_usage(tenant_id,snapshot_count,logical_bytes)
                 VALUES($1,$2,$2) ON CONFLICT(tenant_id) DO UPDATE
                 SET snapshot_count=$2,logical_bytes=$2",
                &[&tenant, &seeded],
            )
            .await?;
        drop(client);

        // Four concurrent creators race for the single remaining slot.
        let mut tasks = Vec::new();
        for _ in 0..4 {
            let pool = pool.clone();
            let (_, request) = create_request(scope(repo, tenant, history), version.digest(), LEASE);
            tasks.push(tokio::spawn(async move { create(&pool, &request).await }));
        }
        let mut granted = Vec::new();
        let mut refused = 0;
        for task in tasks {
            match task.await? {
                Ok(outcome) => granted.push(outcome),
                Err(RefStoreError::MetadataQuotaExceeded { scope, .. }) => {
                    assert_eq!(scope, rootyard::ref_store::MetadataQuotaScope::Repository);
                    refused += 1;
                }
                Err(other) => panic!("unexpected racing create error: {other}"),
            }
        }
        assert_eq!(granted.len(), 1, "exactly one creator may take the last retained slot");
        assert_eq!(refused, 3);
        let counters = usage(&pool, repo, tenant).await?;
        assert_eq!(counters.0, REPO_MAX_SNAPSHOTS, "usage must be exactly full");
        assert_eq!(counts(&pool, repo).await?.0, REPO_MAX_SNAPSHOTS);

        // Release does not refund the retained slot: the budget stays full.
        release(
            &pool,
            &ReleaseMetadataPinRequest::new(
                scope(repo, tenant, history),
                Uuid::new_v4(),
                granted[0].receipt.pin_id(),
                1,
                PinReleaseReason::ClientDone,
            )?,
        )
        .await?;
        let (_, after) = create_request(scope(repo, tenant, history), version.digest(), LEASE);
        match create(&pool, &after).await {
            Err(RefStoreError::MetadataQuotaExceeded { scope, resource }) => {
                assert_eq!(scope, rootyard::ref_store::MetadataQuotaScope::Repository);
                assert_eq!(resource, rootyard::ref_store::MetadataQuotaResource::Snapshots);
            }
            other => panic!("release must not refund retained quota: {other:?}"),
        }
        assert_eq!(usage(&pool, repo, tenant).await?.0, REPO_MAX_SNAPSHOTS);
        Ok::<(), anyhow::Error>(())
    }
    .await;
    finish(&admin, &schema, outcome).await
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn unknown_lookups_and_metadata_capabilities() -> Result<()> {
    let (admin, pool, schema, tenant, repo) = setup().await?;
    let outcome = async {
        let history = Uuid::new_v4();
        initialize_and_seed(&pool, repo, tenant, history).await?;
        let version = gate_version(&pool, repo, tenant).await?;
        let (_, request) = create_request(scope(repo, tenant, history), version.digest(), LEASE);
        let created = create(&pool, &request).await?;

        let missing = ReadMetadataSnapshotPageRequest::new(
            scope(repo, tenant, history),
            created.receipt.snapshot_id(),
            Uuid::new_v4(),
            1,
            None,
            None,
            8,
        )?;
        assert!(matches!(page(&pool, &missing).await, Err(RefStoreError::MetadataPinNotFound { .. })));
        assert!(matches!(
            lookup(&pool, &scope(repo, tenant, history), Uuid::new_v4()).await?,
            MetadataReceiptLookup::Unknown
        ));
        // A receipt is only resolvable inside its own repository scope.
        let other_repo = Uuid::new_v4();
        assert!(matches!(
            lookup(&pool, &scope(other_repo, tenant, history), request.request_id()).await,
            Err(RefStoreError::RepositoryNotFound)
        ));

        let capabilities = PgRefStoreCore.capabilities();
        assert!(capabilities.metadata_snapshot_capture);
        assert!(capabilities.metadata_snapshot_pagination);
        assert!(capabilities.metadata_pin_lease);
        assert!(capabilities.metadata_quota_admission);
        assert!(!capabilities.pack_membership_snapshot);
        assert!(!capabilities.atomic_read_snapshot);
        assert!(!capabilities.durable_snapshot_pin);
        assert!(!capabilities.gc_observes_pins);
        assert!(!capabilities.logical_roots);
        assert!(!capabilities.artifact_holds);
        assert!(!capabilities.serving_cutover);
        assert!(!capabilities.client_idempotent_publish);
        Ok::<(), anyhow::Error>(())
    }
    .await;
    finish(&admin, &schema, outcome).await
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn expired_and_released_replays_never_extend_or_revive() -> Result<()> {
    let (admin, pool, schema, tenant, repo) = setup().await?;
    let outcome = async {
        let history = Uuid::new_v4();
        initialize_and_seed(&pool, repo, tenant, history).await?;
        let version = gate_version(&pool, repo, tenant).await?;
        let scope = scope(repo, tenant, history);
        let short_lease = 3;
        let (_, create_req) = create_request(scope, version.digest(), short_lease);
        let created = create(&pool, &create_req).await?.receipt;
        assert_eq!(created.pin_generation(), 1);
        let pin_id = created.pin_id();
        let snapshot_id = created.snapshot_id();

        let renew_req = RenewMetadataPinRequest::new(scope, Uuid::new_v4(), pin_id, 1, short_lease)?;
        let renewed = renew(&pool, &renew_req).await?;
        assert!(!renewed.replayed);
        assert_eq!(renewed.receipt.pin_generation(), 2);
        let charged = usage(&pool, repo, tenant).await?;
        assert_eq!((charged.0, charged.1, charged.3), (1, 3, 2));
        let live = pin_status(&pool, pin_id).await?;
        assert_eq!(live, ("active".to_owned(), 2, renewed.receipt.expires_at_unix_micros()));

        wait_past_pin_expiry(&pool, pin_id).await?;

        // Exact historical replays after expiry return the immutable receipt
        // bodies but must not extend the lease, advance the generation or
        // recharge retained usage.
        let create_replay = create(&pool, &create_req).await?;
        assert!(create_replay.replayed);
        assert_eq!(create_replay.receipt, created);
        assert_eq!(pin_status(&pool, pin_id).await?, live, "create replay touched the expired pin");
        let renew_replay = renew(&pool, &renew_req).await?;
        assert!(renew_replay.replayed);
        assert_eq!(renew_replay.receipt, renewed.receipt);
        assert_eq!(pin_status(&pool, pin_id).await?, live, "renew replay extended the expired lease");
        assert_eq!(usage(&pool, repo, tenant).await?, charged, "replays charged retained usage");
        assert_eq!(counts(&pool, repo).await?, (1, 3, 1, 2));

        // New page and renew calls stay denied by the database clock: the old
        // renew receipt is history, not a live grant.
        let expired_page = ReadMetadataSnapshotPageRequest::new(scope, snapshot_id, pin_id, 2, None, None, 8)?;
        match page(&pool, &expired_page).await {
            Err(RefStoreError::MetadataPinExpired { pin_id: denied, generation }) => {
                assert_eq!((denied, generation), (pin_id, 2));
            }
            other => panic!("expired page must be typed expired: {other:?}"),
        }
        match renew(&pool, &RenewMetadataPinRequest::new(scope, Uuid::new_v4(), pin_id, 2, 60)?).await {
            Err(RefStoreError::MetadataPinExpired { pin_id: denied, generation }) => {
                assert_eq!((denied, generation), (pin_id, 2));
            }
            other => panic!("expired renew must be typed expired: {other:?}"),
        }

        // The exact release after expiry is positive and terminal.
        let released = release(
            &pool,
            &ReleaseMetadataPinRequest::new(scope, Uuid::new_v4(), pin_id, 2, PinReleaseReason::LeaseAbandoned)?,
        )
        .await?;
        assert_eq!(released.receipt.action(), MetadataMutationAction::Release);
        assert_eq!(released.receipt.pin_generation(), 2);
        assert!(released.receipt.released_at_unix_micros().is_some());
        let terminal = pin_status(&pool, pin_id).await?;
        assert_eq!(terminal.0, "released");
        assert_eq!(terminal.1, 2);
        let after_release = usage(&pool, repo, tenant).await?;
        assert_eq!((after_release.0, after_release.1, after_release.3), (1, 3, 3));

        // Exact replays after release still return the historical bodies and
        // still do not revive the terminal pin.
        let create_after = create(&pool, &create_req).await?;
        assert!(create_after.replayed);
        assert_eq!(create_after.receipt, created);
        let renew_after = renew(&pool, &renew_req).await?;
        assert!(renew_after.replayed);
        assert_eq!(renew_after.receipt, renewed.receipt);
        assert_eq!(pin_status(&pool, pin_id).await?, terminal, "a replay revived a released pin");
        assert_eq!(usage(&pool, repo, tenant).await?, after_release, "post-release replays charged usage");
        assert_eq!(counts(&pool, repo).await?, (1, 3, 1, 3));

        let released_page = ReadMetadataSnapshotPageRequest::new(scope, snapshot_id, pin_id, 2, None, None, 8)?;
        assert!(matches!(page(&pool, &released_page).await, Err(RefStoreError::MetadataPinReleased { .. })));
        assert!(matches!(
            renew(&pool, &RenewMetadataPinRequest::new(scope, Uuid::new_v4(), pin_id, 2, 60)?).await,
            Err(RefStoreError::MetadataPinReleased { .. })
        ));
        assert!(matches!(
            release(
                &pool,
                &ReleaseMetadataPinRequest::new(
                    scope,
                    Uuid::new_v4(),
                    pin_id,
                    2,
                    PinReleaseReason::MaintenanceComplete,
                )?
            )
            .await,
            Err(RefStoreError::MetadataPinReleased { .. })
        ));
        Ok::<(), anyhow::Error>(())
    }
    .await;
    finish(&admin, &schema, outcome).await
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn non_ascii_refs_page_with_literal_prefix_and_cursor() -> Result<()> {
    let (admin, pool, schema, tenant, repo) = setup().await?;
    let outcome = async {
        let history = Uuid::new_v4();
        initialize(&pool, &gate(repo, tenant, history)).await?;
        // No ref may be a strict path prefix of another inside one repository,
        // so the Unicode prefix exercise uses siblings and a literal sibling.
        let names = [
            ("refs/heads/e", 1),
            ("refs/heads/main", 2),
            ("refs/heads/é/a", 3),
            ("refs/heads/é/b", 4),
            ("refs/heads/éx", 5),
            ("refs/heads/ê", 6),
            ("refs/tags/v1", 7),
        ];
        let updates = names.iter().map(|(name, byte)| update(name, None, Some(oid(*byte)))).collect::<Vec<_>>();
        let mut client = pool.get().await?;
        let committed = PgRefStoreCore
            .commit_refs(&mut client, &commit_request(repo, tenant, 1, Uuid::new_v4(), history, 1, updates), deadline())
            .await?;
        assert!(committed.is_committed());
        drop(client);

        let version = gate_version(&pool, repo, tenant).await?;
        assert_eq!(version.revision(), 2);
        let scope = scope(repo, tenant, history);
        let (_, request) = create_request(scope, version.digest(), LEASE);
        let created = create(&pool, &request).await?.receipt;
        let expected = names.iter().map(|(name, byte)| ((*name).to_owned(), oid(*byte))).collect::<Vec<_>>();

        let all = page(
            &pool,
            &ReadMetadataSnapshotPageRequest::new(scope, created.snapshot_id(), created.pin_id(), 1, None, None, 256)?,
        )
        .await?;
        assert!(all.complete());
        assert_eq!(all.ref_count(), 7);
        let listed = all.refs().iter().map(|entry| (entry.name().as_str().to_owned(), entry.oid())).collect::<Vec<_>>();
        assert_eq!(listed, expected, "byte-ordered non-ASCII refs must be captured and listed exactly");

        // Bounded page-1 cursor walk: every row exactly once, in byte order.
        let mut walked = Vec::new();
        let mut cursor = None;
        for _ in 0..16 {
            let request = ReadMetadataSnapshotPageRequest::new(
                scope,
                created.snapshot_id(),
                created.pin_id(),
                1,
                None,
                cursor.clone(),
                2,
            )?;
            let current = page(&pool, &request).await?;
            assert!(current.refs().len() <= 2);
            for entry in current.refs() {
                walked.push((entry.name().as_str().to_owned(), entry.oid()));
            }
            match current.next().cloned() {
                Some(next) => {
                    assert!(!current.complete());
                    cursor = Some(next);
                }
                None => {
                    assert!(current.complete());
                    break;
                }
            }
        }
        assert_eq!(walked, expected, "bounded page-1 cursor walk must be complete and ordered");

        // A literal non-ASCII prefix must compare bytes, not treat the UTF-8
        // continuation bytes as extra SQL characters.
        let prefix = RefPrefix::new("refs/heads/é")?;
        let first = page(
            &pool,
            &ReadMetadataSnapshotPageRequest::new(
                scope,
                created.snapshot_id(),
                created.pin_id(),
                1,
                Some(prefix.clone()),
                None,
                2,
            )?,
        )
        .await?;
        assert_eq!(
            first.refs().iter().map(|entry| entry.name().as_str()).collect::<Vec<_>>(),
            vec!["refs/heads/é/a", "refs/heads/é/b"]
        );
        assert!(!first.complete());
        let next = first.next().cloned().expect("non-ASCII prefix page must yield a cursor");
        let second = page(
            &pool,
            &ReadMetadataSnapshotPageRequest::new(
                scope,
                created.snapshot_id(),
                created.pin_id(),
                1,
                Some(prefix),
                Some(next),
                2,
            )?,
        )
        .await?;
        assert_eq!(second.refs().iter().map(|entry| entry.name().as_str()).collect::<Vec<_>>(), vec!["refs/heads/éx"]);
        assert!(second.complete());

        // A trailing slash is a literal boundary and excludes the sibling.
        let slashed = page(
            &pool,
            &ReadMetadataSnapshotPageRequest::new(
                scope,
                created.snapshot_id(),
                created.pin_id(),
                1,
                Some(RefPrefix::new("refs/heads/é/")?),
                None,
                256,
            )?,
        )
        .await?;
        assert_eq!(
            slashed.refs().iter().map(|entry| entry.name().as_str()).collect::<Vec<_>>(),
            vec!["refs/heads/é/a", "refs/heads/é/b"]
        );
        assert!(slashed.complete());
        Ok::<(), anyhow::Error>(())
    }
    .await;
    finish(&admin, &schema, outcome).await
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn oversize_capture_is_typed_and_writes_no_metadata_or_quota() -> Result<()> {
    let (admin, pool, schema, tenant, repo) = setup().await?;
    let outcome = async {
        let history = Uuid::new_v4();
        initialize(&pool, &gate(repo, tenant, history)).await?;
        // 128 is the commit batch limit, not the repository/ref budget: 32 full
        // legitimate commits plus one add 4097 refs through the adapter itself.
        for chunk in 0_i64..33 {
            let revision = chunk + 1;
            let count = if chunk == 32 { 1_i64 } else { 128_i64 };
            let updates = (0..count)
                .map(|offset| {
                    let index = chunk * 128 + offset;
                    update(&format!("refs/heads/bulk/{index:04}"), None, Some(oid(1)))
                })
                .collect::<Vec<_>>();
            let mut client = pool.get().await?;
            let committed = PgRefStoreCore
                .commit_refs(
                    &mut client,
                    &commit_request(repo, tenant, revision, Uuid::new_v4(), history, revision, updates),
                    deadline(),
                )
                .await?;
            assert!(committed.is_committed());
        }
        let version = gate_version(&pool, repo, tenant).await?;
        assert_eq!(version.revision(), 34);
        let scope = scope(repo, tenant, history);
        let (_, request) = create_request(scope, version.digest(), LEASE);
        match create(&pool, &request).await {
            Err(RefStoreError::MetadataSnapshotTooLarge { ref_count, max_refs }) => {
                assert_eq!(ref_count, 4097);
                assert_eq!(max_refs, 4096);
            }
            other => panic!("oversize capture must be typed too-large: {other:?}"),
        }
        assert_eq!(counts(&pool, repo).await?, (0, 0, 0, 0), "rejected capture wrote metadata rows");
        assert_eq!(
            usage(&pool, repo, tenant).await?,
            (0, 0, 0, 0, 0, 0, 0, 0),
            "rejected capture charged retained quota"
        );

        // Deleting one ref proves the rejected transaction left no partial rows
        // or poisoned quota: the exact 4096 boundary is still capturable.
        let mut client = pool.get().await?;
        let deleted = PgRefStoreCore
            .commit_refs(
                &mut client,
                &commit_request(
                    repo,
                    tenant,
                    34,
                    Uuid::new_v4(),
                    history,
                    34,
                    vec![update("refs/heads/bulk/4096", Some(oid(1)), None)],
                ),
                deadline(),
            )
            .await?;
        assert!(deleted.is_committed());
        drop(client);
        let version = gate_version(&pool, repo, tenant).await?;
        assert_eq!(version.revision(), 35);
        let (_, boundary) = create_request(scope, version.digest(), LEASE);
        let created = create(&pool, &boundary).await?;
        assert_eq!(created.receipt.ref_count(), 4096);
        assert_eq!(counts(&pool, repo).await?, (1, 4096, 1, 1));
        let charged = usage(&pool, repo, tenant).await?;
        assert_eq!((charged.0, charged.1, charged.3), (1, 4096, 1));
        assert!(charged.2 > 0);
        Ok::<(), anyhow::Error>(())
    }
    .await;
    finish(&admin, &schema, outcome).await
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn renew_after_live_check_observes_expiry_without_charge() -> Result<()> {
    let (admin, pool, schema, tenant, repo) = setup().await?;
    let outcome = async {
        let history = Uuid::new_v4();
        initialize_and_seed(&pool, repo, tenant, history).await?;
        let version = gate_version(&pool, repo, tenant).await?;
        let scope = scope(repo, tenant, history);
        let (_, create_req) = create_request(scope, version.digest(), 3);
        let created = create(&pool, &create_req).await?.receipt;
        let pin_id = created.pin_id();
        let before_usage = usage(&pool, repo, tenant).await?;
        let before_status = pin_status(&pool, pin_id).await?;
        assert_eq!(before_status.0, "active");
        assert_eq!(before_status.1, 1);

        let key = i64::from_be_bytes(Uuid::new_v4().into_bytes()[..8].try_into().expect("eight bytes"));
        let barrier = acquire_barrier(&pool, key).await?;
        install_renew_update_barrier(&pool, key).await?;

        let renew_id = Uuid::new_v4();
        let renew_req = RenewMetadataPinRequest::new(scope, renew_id, pin_id, 1, 60)?;
        let mut client = pool.get().await?;
        let pid: i32 = client.query_one("SELECT pg_backend_pid()", &[]).await?.get(0);
        let renew_task = tokio::spawn(async move {
            PgRefStoreCore.renew_metadata_pin(&mut client, &renew_req, Instant::now() + Duration::from_secs(15)).await
        });
        // The statement trigger is reached only after the adapter's live pin
        // check, so the parked UPDATE proves that prior check passed.
        wait_for_advisory_wait(&pool, pid).await?;
        wait_past_pin_expiry(&pool, pin_id).await?;
        barrier.release().await?;
        let result = tokio::time::timeout(Duration::from_secs(10), renew_task)
            .await
            .context("renew did not settle after the expiry interleaving")??;
        match result {
            Err(RefStoreError::MetadataPinExpired { pin_id: denied, generation }) => {
                assert_eq!((denied, generation), (pin_id, 1));
            }
            other => panic!("renew must re-check expiry after the live check and before the UPDATE lands: {other:?}"),
        }
        assert_eq!(pin_status(&pool, pin_id).await?, before_status, "failed renew changed the pin row");
        assert_eq!(usage(&pool, repo, tenant).await?, before_usage, "failed renew charged retained usage");
        assert_eq!(counts(&pool, repo).await?, (1, 3, 1, 1), "failed renew wrote a receipt");
        assert!(matches!(lookup(&pool, &scope, renew_id).await?, MetadataReceiptLookup::Unknown));
        drop_renew_update_barrier(&pool).await?;
        Ok::<(), anyhow::Error>(())
    }
    .await;
    finish(&admin, &schema, outcome).await
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn direct_sql_scope_fks_and_delete_guards_are_durable() -> Result<()> {
    let (admin, pool, schema, tenant, repo) = setup().await?;
    let outcome = async {
        let history = Uuid::new_v4();
        initialize_and_seed(&pool, repo, tenant, history).await?;
        let version = gate_version(&pool, repo, tenant).await?;
        let (_, request) = create_request(scope(repo, tenant, history), version.digest(), LEASE);
        let created = create(&pool, &request).await?.receipt;
        let client = pool.get().await?;

        // Clone the header only inside this failing statement so the probe has
        // no existing pin and cannot stop at the one-pin-per-snapshot UNIQUE.
        // The repository and tenant are valid; only the owner disagrees with
        // the immutable header, exercising the full-scope snapshot FK itself.
        // The failing statement also rolls back its temporary header.
        let wrong_owner = Uuid::new_v4();
        let error = client
            .execute(
                "WITH probe AS (
                     INSERT INTO ref_store_core_snapshots(
                         snapshot_id,repository_id,tenant_id,owner_id,purpose,object_format,
                         history_incarnation,authority_epoch,group_epoch,gate_revision,gate_digest,
                         head_ref,head_oid,ref_count,refs_digest,logical_bytes)
                     SELECT $4,repository_id,tenant_id,owner_id,purpose,object_format,
                         history_incarnation,authority_epoch,group_epoch,gate_revision,gate_digest,
                         head_ref,head_oid,ref_count,refs_digest,logical_bytes
                     FROM ref_store_core_snapshots WHERE snapshot_id=$8
                     RETURNING snapshot_id
                 ) INSERT INTO ref_store_core_pins(
                     pin_id,repository_id,tenant_id,snapshot_id,owner_id,purpose,create_request_id,
                     create_digest,generation,state,expires_at)
                 SELECT $1,$2,$3,probe.snapshot_id,$5,'verification',$6,$7,1,'active',
                        clock_timestamp()+interval '60 seconds' FROM probe",
                &[
                    &Uuid::new_v4(),
                    &repo,
                    &tenant,
                    &Uuid::new_v4(),
                    &wrong_owner,
                    &Uuid::new_v4(),
                    &"a".repeat(64),
                    &created.snapshot_id(),
                ],
            )
            .await
            .expect_err("wrong-scope pin insert must be rejected");
        assert_eq!(error.code().map(|code| code.code()), Some("23503"));

        // A receipt cannot bind a different snapshot than its pin: the combined
        // parent key also answers SQLSTATE 23503.
        let error = client
            .execute(
                "INSERT INTO ref_store_core_receipts(
                     request_id,repository_id,tenant_id,action,request_digest,pin_id,snapshot_id,pin_generation,body)
                 VALUES($1,$2,$3,'renew',$4,$5,$6,1,'{}')",
                &[
                    &Uuid::new_v4(),
                    &repo,
                    &tenant,
                    &"b".repeat(64),
                    &created.pin_id(),
                    &Uuid::new_v4(),
                ],
            )
            .await
            .expect_err("wrong-scope receipt insert must be rejected");
        assert_eq!(error.code().map(|code| code.code()), Some("23503"));

        let retained_before_delete = usage(&pool, repo, tenant).await?;
        // Direct identity deletes are refused while the repository exists.
        for statement in [
            "DELETE FROM ref_store_core_receipts WHERE repository_id=$1",
            "DELETE FROM ref_store_core_pins WHERE repository_id=$1",
            "DELETE FROM ref_store_core_snapshots WHERE repository_id=$1",
            "DELETE FROM ref_store_core_snapshot_refs WHERE snapshot_id IN (SELECT snapshot_id FROM ref_store_core_snapshots WHERE repository_id=$1)",
            "DELETE FROM ref_store_core_repo_usage WHERE repository_id=$1",
            "DELETE FROM ref_store_core_tenant_usage WHERE tenant_id=(SELECT owner_id FROM repositories WHERE id=$1)",
        ] {
            let error = client.execute(statement, &[&repo]).await.expect_err("direct delete must be guarded");
            assert_eq!(error.code().map(|code| code.code()), Some("P0001"));
        }
        assert_eq!(counts(&pool, repo).await?, (1, 3, 1, 1), "guarded deletes removed metadata");
        drop(client);

        // Only the whole-repository cascade at the end may remove retained
        // identities, and a deleted identity cannot be resurrected by a create.
        pool.get().await?.execute("DELETE FROM repositories WHERE id=$1", &[&repo]).await?;
        assert_eq!(counts(&pool, repo).await?, (0, 0, 0, 0), "repository cascade left metadata rows");
        let retained = usage(&pool, repo, tenant).await?;
        assert_eq!((retained.0, retained.1, retained.2, retained.3), (0, 0, 0, 0));
        assert_eq!((retained.4, retained.5, retained.6, retained.7),
            (retained_before_delete.4, retained_before_delete.5, retained_before_delete.6, retained_before_delete.7),
            "repository deletion must not refund retained tenant usage");
        pool.get().await?.execute("DELETE FROM users WHERE id=$1", &[&tenant]).await?;
        assert_eq!(usage(&pool, repo, tenant).await?, (0, 0, 0, 0, 0, 0, 0, 0), "tenant cascade left retained usage");
        let (_, stale) = create_request(scope(repo, tenant, history), version.digest(), LEASE);
        match create(&pool, &stale).await {
            Err(RefStoreError::RepositoryNotFound) => {}
            other => panic!("deleted repository must not accept metadata creates: {other:?}"),
        }
        Ok::<(), anyhow::Error>(())
    }
    .await;
    finish(&admin, &schema, outcome).await
}

/// A successful receipt body is immutable audit data, so a stored ledger row
/// whose body disagrees with the immutable snapshot summary, or with its own
/// ledger key, must be a typed denial and never replay as `Found`. Every case
/// below is a *corrupt ledger* fixture written with plain SQL (fresh request-id
/// PK, valid pin/snapshot FKs, action `create`, generation 1) and derived from
/// the real stored receipt: no receipt body is trusted on its own. The same
/// fixture proves the durable pin guard refuses direct DML that would revive an
/// expired active lease or exceed the 3600-second renewal maximum.
#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn corrupt_ledger_bodies_and_direct_pin_rewrites_are_typed_denials() -> Result<()> {
    let (admin, pool, schema, tenant, repo) = setup().await?;
    let outcome = async {
        let history = Uuid::new_v4();
        initialize_and_seed(&pool, repo, tenant, history).await?;
        let version = gate_version(&pool, repo, tenant).await?;
        let scope = scope(repo, tenant, history);
        let (_, request) = create_request(scope, version.digest(), LEASE);
        let created = create(&pool, &request).await?.receipt;
        assert_eq!(created.pin_generation(), 1, "fixture pin must still be generation 1");
        let client = pool.get().await?;
        let stored: String = client
            .query_one("SELECT body FROM ref_store_core_receipts WHERE request_id=$1", &[&created.request_id()])
            .await?
            .get(0);
        let stored: serde_json::Value = serde_json::from_str(&stored)?;
        let retained = usage(&pool, repo, tenant).await?;

        // One corrupt summary field at a time, everything else byte-identical to
        // the real receipt except the request id, which must match the new row
        // PK so decoding reaches the immutable-header comparison.
        let corruptions: [(&str, serde_json::Value); 7] = [
            ("head_ref", json!("refs/heads/corrupt")),
            ("head_oid", json!("0".repeat(40))),
            ("gate_revision", json!(stored["gate_revision"].as_i64().expect("stored gate revision") + 1)),
            ("gate_digest", json!("c".repeat(64))),
            ("ref_count", json!(stored["ref_count"].as_i64().expect("stored ref count") + 1)),
            ("refs_digest", json!("d".repeat(64))),
            ("logical_bytes", json!(stored["logical_bytes"].as_i64().expect("stored logical bytes") + 1)),
        ];
        let insert = "INSERT INTO ref_store_core_receipts(
                          request_id,repository_id,tenant_id,action,request_digest,pin_id,snapshot_id,pin_generation,body)
                      VALUES($1,$2,$3,'create',$4,$5,$6,1,$7)";
        for (field, corrupted) in corruptions {
            let request_id = Uuid::new_v4();
            let mut body = stored.clone();
            body["request_id"] = json!(request_id);
            body[field] = corrupted;
            client
                .execute(
                    insert,
                    &[&request_id, &repo, &tenant, &"e".repeat(64), &created.pin_id(), &created.snapshot_id(), &serde_json::to_string(&body)?],
                )
                .await?;
            match lookup(&pool, &scope, request_id).await {
                Err(RefStoreError::MetadataScopeMismatch(reason)) => {
                    assert_eq!(reason, "stored receipt snapshot summary", "corrupt {field} escaped the summary guard")
                }
                other => panic!("corrupt receipt summary {field} must be a typed summary denial, not {other:?}"),
            }
        }

        // The outer ledger key is authoritative before any summary comparison: a
        // body that still names the original request id is refused, so the
        // summary cases above cannot be passing by failing somewhere earlier.
        let request_id = Uuid::new_v4();
        client
            .execute(
                insert,
                &[&request_id, &repo, &tenant, &"e".repeat(64), &created.pin_id(), &created.snapshot_id(), &serde_json::to_string(&stored)?],
            )
            .await?;
        match lookup(&pool, &scope, request_id).await {
            Err(RefStoreError::Database(message)) => assert!(
                message.contains("immutable ledger row"),
                "outer/body request-id disagreement must be the ledger guard: {message}"
            ),
            other => panic!("a receipt body with a stale request id must not replay: {other:?}"),
        }
        // The untouched original receipt still replays, and none of these plain
        // SQL fixtures fabricated retained usage.
        assert!(matches!(lookup(&pool, &scope, created.request_id()).await?, MetadataReceiptLookup::Found(_)));
        assert_eq!(usage(&pool, repo, tenant).await?, retained, "corrupt fixtures charged retained usage");

        // An expired *active* pin cannot be renewed by direct DML: the generation
        // advance and the new +60s lease satisfy every other pin-guard rule, so
        // only the OLD-expiry rule can answer P0001, and the row stays untouched.
        let (_, short) = create_request(scope, version.digest(), 1);
        let expiring = create(&pool, &short).await?.receipt;
        wait_past_pin_expiry(&pool, expiring.pin_id()).await?;
        let expired_before = pin_status(&pool, expiring.pin_id()).await?;
        let error = client
            .execute(
                "UPDATE ref_store_core_pins SET generation=generation+1,renewed_at=clock_timestamp(),
                        updated_at=clock_timestamp(),expires_at=clock_timestamp()+interval '60 seconds'
                  WHERE pin_id=$1",
                &[&expiring.pin_id()],
            )
            .await
            .expect_err("direct renewal of an expired active pin must be refused");
        assert_eq!(error.code().map(|code| code.code()), Some("P0001"));
        assert_eq!(pin_status(&pool, expiring.pin_id()).await?, expired_before, "rejected renewal changed the pin row");

        // A live pin is still bounded by the 3600-second contract maximum; that
        // limit is the only guard rule this UPDATE violates, and it leaves the
        // lease and retained usage untouched.
        let (_, live) = create_request(scope, version.digest(), LEASE);
        let live = create(&pool, &live).await?.receipt;
        let retained = usage(&pool, repo, tenant).await?;
        let live_before = pin_status(&pool, live.pin_id()).await?;
        let error = client
            .execute(
                "UPDATE ref_store_core_pins SET generation=generation+1,renewed_at=clock_timestamp(),
                        updated_at=clock_timestamp(),expires_at=clock_timestamp()+interval '3601 seconds'
                  WHERE pin_id=$1",
                &[&live.pin_id()],
            )
            .await
            .expect_err("direct renewal beyond the 3600-second maximum must be refused");
        assert_eq!(error.code().map(|code| code.code()), Some("P0001"));
        assert_eq!(pin_status(&pool, live.pin_id()).await?, live_before, "rejected renewal changed the live pin row");
        assert_eq!(usage(&pool, repo, tenant).await?, retained, "rejected pin updates charged retained usage");
        Ok::<(), anyhow::Error>(())
    }
    .await;
    finish(&admin, &schema, outcome).await
}
