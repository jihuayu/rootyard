//! S4 CI pin producer for `pg_refstore` repositories.
//!
//! A pin is the pair of one durable, non-expiring `PgRetentionRoots` capture and
//! one `s4_ci_retention.ci_pins` row written in the *same* PostgreSQL
//! transaction. There is therefore no observable state in which a pin exists
//! without its retained root: the capture is prepared outside PostgreSQL
//! (verified Blob/native closure) and only becomes durable with the business row.
use super::s4_models::{S4PinView, fixed_oid};
use super::s4_schema::ensure_s4_schema;
use super::*;
use crate::blob_store::{config::BlobProfile, opendal::BlobStore};
use crate::ref_store::{
    MetadataPinPurpose, PinReleaseReason, ReleaseMetadataPinRequest, RootPurpose, RootSelector,
    contract::RequestDigest,
    core::{
        CreatePackSnapshotRequest, MetadataSnapshotScope, PackSnapshotExpectation, PackSnapshotRef, PgPackSnapshot,
        pack_commit::packs_digest,
        retention_root::{PgRetentionRoots, PrepareRootRequest, RegisterRootRequest, RootError},
    },
    serving::{ServingRepository, lookup},
};
use tokio::time::Instant;

/// Caller-fixed identity and intent of one capture. Grouping the fields keeps
/// the producer within the seven-argument bound.
pub(crate) struct CaptureSpec<'a> {
    pub(crate) purpose: RootPurpose,
    pub(crate) business_intent: &'a str,
    pub(crate) target_oid: &'a str,
}

/// Outcome of one verified capture, before its durable registration.
pub(crate) struct Prepared {
    pub(crate) request: RegisterRootRequest,
    pub(crate) snapshot: PackSnapshotRef,
    pub(crate) snapshot_scope: MetadataSnapshotScope,
    pub(crate) pack_set_digest: String,
}

/// One opened Blob store plus the root adapter built from exactly that store.
pub(crate) struct Producer {
    pub(crate) store: BlobStore,
    pub(crate) roots: PgRetentionRoots,
}

impl Producer {
    pub(crate) fn open(state: &AppState) -> Result<Self, Error> {
        let profile = BlobProfile::from_env().map_err(Error::internal)?;
        let store = BlobStore::open(profile).map_err(Error::internal)?;
        let roots =
            PgRetentionRoots::new(store.clone(), state.config.git.clone()).map_err(Error::internal)?;
        Ok(Self { store, roots })
    }

    /// Short-lease serving snapshot, then the full native/Blob closure proof
    /// outside every PostgreSQL transaction. Nothing durable is written here.
    pub(crate) async fn capture(
        &self,
        pool: &deadpool_postgres::Pool,
        serving: &ServingRepository,
        spec: CaptureSpec<'_>,
        deadline: Instant,
    ) -> Result<Prepared, Error> {
        let gate = &serving.gate;
        let owner_id = serving.gate.tenant_id();
        let repository_id = serving.repository.id;
        let scope = MetadataSnapshotScope::new(
            repository_id,
            gate.tenant_id(),
            owner_id,
            MetadataPinPurpose::Verification,
            gate.object_format(),
            gate.history_incarnation(),
            gate.authority_epoch(),
            gate.group_epoch(),
        )
        .map_err(Error::internal)?;
        let snapshot_id = Uuid::new_v4();
        let pin_id = Uuid::new_v4();
        let snapshot_request = Uuid::new_v4();
        let mut client = pool.get().await.map_err(Error::internal)?;
        let tx = client.transaction().await.map_err(Error::internal)?;
        PgPackSnapshot
            .serving_request_lock(&tx, snapshot_request, deadline)
            .await
            .map_err(|_| Error(StatusCode::CONFLICT, "serving snapshot request refused"))?;
        let expected = match PgPackSnapshot
            .serving_create_expectation(&tx, &scope, snapshot_request, pin_id, snapshot_id, deadline)
            .await
            .map_err(|_| Error(StatusCode::CONFLICT, "live serving expectation is unavailable"))?
        {
            Some(expected) => expected,
            None => PackSnapshotExpectation::new(gate.revision(), *gate.digest())
                .map_err(|_| Error::internal("fresh pack snapshot expectation is invalid"))?,
        };
        let create = CreatePackSnapshotRequest::new(
            scope,
            snapshot_request,
            pin_id,
            snapshot_id,
            120,
            expected,
        )
        .map_err(|error| root_error(RootError::from(error)))?;
        let outcome = PgPackSnapshot
            .create_serving_checked(&tx, &create, self.store.backend_identity().as_hex(), deadline)
            .await
            .map_err(|_| Error(StatusCode::CONFLICT, "serving snapshot creation refused"))?;
        commit_owned(tx, deadline).await?;
        drop(client);

        let root_scope = crate::ref_store::core::retention_root::RootsScope::new(
            repository_id,
            gate.tenant_id(),
            owner_id,
            spec.purpose,
            spec.business_intent,
            gate.object_format(),
            gate.history_incarnation(),
            gate.authority_epoch(),
            gate.group_epoch(),
        )
        .map_err(root_error)?;
        let snapshot = PackSnapshotRef::new(
            repository_id,
            gate.tenant_id(),
            outcome.receipt.snapshot_id(),
            outcome.receipt.pin_id(),
            outcome.receipt.pin_generation(),
        )
        .map_err(|error| root_error(RootError::from(error)))?;
        let register_request = Uuid::new_v4();
        let prepare = PrepareRootRequest::new(
            root_scope,
            snapshot,
            Uuid::new_v4(),
            Uuid::new_v4(),
            RootSelector::ObjectIds(vec![spec.target_oid.to_owned()]),
            register_request,
        )
        .map_err(root_error)?;
        let candidate = self
            .roots
            .prepare_serving(pool, prepare, deadline)
            .await
            .map_err(root_error)?;
        let pack_set_digest = packs_digest(candidate.packs()).as_hex();
        let request = RegisterRootRequest::new(candidate, register_request).map_err(root_error)?;
        Ok(Prepared { request, snapshot, snapshot_scope: scope, pack_set_digest })
    }

    /// Drop the transient 120 s source snapshot pin once the durable root (and,
    /// for a view, the business row) is committed. Retained packs carry their own
    /// `RetentionRoot` row and locators, so the permanent protection is untouched;
    /// releasing here keeps one repository far below the 64-pin A5a quota.
    pub(crate) async fn release_source_snapshot(
        &self,
        pool: &deadpool_postgres::Pool,
        scope: MetadataSnapshotScope,
        snapshot: &PackSnapshotRef,
        deadline: Instant,
    ) {
        let Ok(mut client) = pool.get().await else { return };
        let Ok(tx) = client.transaction().await else { return };
        let Ok(request) = ReleaseMetadataPinRequest::new(
            scope,
            Uuid::new_v4(),
            snapshot.pin_id(),
            snapshot.expected_generation(),
            PinReleaseReason::ClientDone,
        ) else {
            return;
        };
        let _ = crate::ref_store::PgRefStoreCore
            .release_serving_checked(&tx, &request, self.store.backend_identity().as_hex(), deadline)
            .await;
        let _ = commit_owned(tx, deadline).await;
    }
}

/// Commit a `deadpool_postgres` transaction under the caller's absolute
/// deadline. An ambiguous COMMIT is reported as retryable, never as success.
pub(crate) async fn commit_owned(
    tx: deadpool_postgres::Transaction<'_>,
    deadline: Instant,
) -> Result<(), Error> {
    if Instant::now() >= deadline {
        let _ = tx.rollback().await;
        return Err(Error::timeout());
    }
    match tokio::time::timeout_at(deadline, tx.commit()).await {
        Ok(Ok(())) => Ok(()),
        _ => Err(Error(
            StatusCode::SERVICE_UNAVAILABLE,
            "ref-store commit outcome is unknown; retry the same request",
        )),
    }
}

/// Map the typed roots refusal to a bounded HTTP vocabulary.
pub(crate) fn root_error(error: RootError) -> Error {
    match error {
        RootError::Store(crate::ref_store::contract::RefStoreError::Timeout) => Error::timeout(),
        RootError::RootReleased { .. } | RootError::RootNotFound { .. } => {
            Error(StatusCode::CONFLICT, "retained root unavailable or released")
        }
        RootError::RootAlreadyActive { .. } | RootError::RootDigestConflict(_) => {
            Error(StatusCode::CONFLICT, "retained root already registered differently")
        }
        _ => Error::internal("retained root request refused"),
    }
}

/// Resolve a repository row only when it is served on `pg_refstore`, so the
/// legacy `gitfs` path keeps its exact behaviour and response codes.
pub(crate) async fn refstore_repository(
    state: &AppState,
    owner: &str,
    name: &str,
) -> Result<Option<db::Repository>, Error> {
    if !db::valid_name(owner) || !db::valid_name(name) {
        return Ok(None);
    }
    let row = state
        .pool
        .get()
        .await
        .map_err(Error::internal)?
        .query_opt(
            &format!("{} WHERE ns.slug=$1 AND r.name=$2", db::REPO_SELECT),
            &[&owner, &name],
        )
        .await
        .map_err(Error::internal)?;
    Ok(row
        .map(|row| db::Repository::from_row(&row))
        .filter(|repo| repo.storage_backend == crate::ref_store::core::serving_scope::PG_REFSTORE_BACKEND))
}

pub(crate) const PIN_COLUMNS: &str = "job_id, repository_id, object_format, target_oid, \
     storage_generation, retention_root_id, register_digest_hex, pack_set_digest_hex, \
     owner_tenant_id, state, issuer_actor_id, authority_epoch, history_incarnation, group_epoch";

pub(crate) fn pin_view(row: &tokio_postgres::Row) -> S4PinView {
    S4PinView {
        job_id: row.get(0),
        repository_id: row.get(1),
        object_format: row.get(2),
        target_oid: row.get(3),
        storage_generation: row.get(4),
        retention_root_id: row.get(5),
        register_digest: row.get(6),
        pack_set_digest: row.get(7),
        state: if row.get::<_, String>(9) == "pinned" { "pinned" } else { "released" },
    }
}

pub(crate) async fn existing_pin(
    tx: &deadpool_postgres::Transaction<'_>,
    repository_id: Uuid,
    job_id: Uuid,
) -> Result<Option<tokio_postgres::Row>, Error> {
    tx.query_opt(
        &format!(
            "SELECT {PIN_COLUMNS} FROM s4_ci_retention.ci_pins \
             WHERE repository_id=$1 AND job_id=$2 FOR UPDATE"
        ),
        &[&repository_id, &job_id],
    )
    .await
    .map_err(Error::internal)
}

/// Serialize `issue` against `cancel`/`revoke` for one exact job inside the
/// caller's transaction, so a concurrent terminal write is never lost.
pub(crate) use super::s4_schema::lock_job;

/// One `ci-pins` create. Exact `(target, generation, tenant)` replay is
/// idempotent; any other reuse of the same job id is a conflict.
pub(crate) async fn pin(
    state: &Arc<AppState>,
    actor: &db::Identity,
    owner: &str,
    name: &str,
    input: &PinRequest,
    deadline: Instant,
) -> Result<Response, Error> {
    ensure_s4_schema(&state.pool).await?;
    let producer = Producer::open(state)?;
    let serving = lookup(
        &state.pool,
        actor,
        owner,
        name,
        true,
        producer.store.backend_identity(),
        deadline,
    )
    .await?;
    let format = serving.repository.object_format.clone();
    let target_oid = fixed_oid(&input.target_oid, &format)?;
    if input.storage_generation <= 0 {
        return Err(Error::bad_request());
    }
    if input.storage_generation != serving.repository.storage_generation {
        return Err(Error(StatusCode::CONFLICT, "repository generation changed"));
    }
    let tenant_id = serving.gate.tenant_id();
    let repository_id = serving.repository.id;

    // Replay is decided before any capture: a duplicate request must never
    // register (and later leak) a second `RetentionRoot` for the same job.
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    crate::ref_store::pg::bound(&tx, deadline)
        .await
        .map_err(|_| Error::timeout())?;
    lock_job(&tx, repository_id, input.job_id).await?;
    if let Some(row) = existing_pin(&tx, repository_id, input.job_id).await? {
        super::s4_authority::guard_repository(
            &tx,
            actor,
            owner,
            name,
            repository_id,
            tenant_id,
            input.storage_generation,
        )
        .await?;
        let same = row.get::<_, String>(3) == target_oid
            && row.get::<_, i64>(4) == input.storage_generation
            && row.get::<_, Uuid>(8) == tenant_id
            && row.get::<_, i64>(11) == serving.gate.authority_epoch()
            && row.get::<_, Uuid>(12) == serving.gate.history_incarnation()
            && row.get::<_, i64>(13) == serving.gate.group_epoch();
        if row.get::<_, String>(9) == "pinned" && same {
            super::s4_authority::ensure_root_active(&tx, repository_id, row.get(5)).await?;
            let body = pin_view(&row);
            commit_owned(tx, deadline).await?;
            drop(client);
            return Ok(([(header::CACHE_CONTROL, "no-store")], Json(body)).into_response());
        }
        return Err(Error(StatusCode::CONFLICT, "job already has a different target or state"));
    }
    let _ = tx.rollback().await;
    drop(client);

    let intent = RequestDigest::of(
        "s4-ci-pin-intent-v1",
        &[
            repository_id.as_bytes(),
            input.job_id.as_bytes(),
            tenant_id.as_bytes(),
            target_oid.as_bytes(),
            &input.storage_generation.to_be_bytes(),
        ],
    )
    .as_hex();
    let prepared = producer
        .capture(
            &state.pool,
            &serving,
            CaptureSpec { purpose: RootPurpose::Ci, business_intent: &intent, target_oid },
            deadline,
        )
        .await?;
    let root_id = prepared.request.candidate().root_id();
    let register_digest = prepared.request.candidate().register_digest().as_hex();
    let pack_set_digest = prepared.pack_set_digest.clone();
    let snapshot_scope = prepared.snapshot_scope;
    let source_snapshot = prepared.snapshot;

    let outcome: Result<Response, Error> = async {
        let mut client = state.pool.get().await.map_err(Error::internal)?;
        let tx = client.transaction().await.map_err(Error::internal)?;
        crate::ref_store::pg::bound(&tx, deadline)
            .await
            .map_err(|_| Error::timeout())?;
        lock_job(&tx, repository_id, input.job_id).await?;
        super::s4_authority::guard_repository(
            &tx,
            actor,
            owner,
            name,
            repository_id,
            tenant_id,
            input.storage_generation,
        )
        .await?;
        // The existence check precedes root registration, so a concurrent
        // duplicate commits its business row but never an unreferenced root.
        if let Some(row) = existing_pin(&tx, repository_id, input.job_id).await? {
            let same = row.get::<_, String>(3) == target_oid
                && row.get::<_, i64>(4) == input.storage_generation
                && row.get::<_, Uuid>(8) == tenant_id
                && row.get::<_, i64>(11) == serving.gate.authority_epoch()
                && row.get::<_, Uuid>(12) == serving.gate.history_incarnation()
                && row.get::<_, i64>(13) == serving.gate.group_epoch();
            if row.get::<_, String>(9) == "pinned" && same {
                super::s4_authority::ensure_root_active(&tx, repository_id, row.get(5)).await?;
                let body = pin_view(&row);
                commit_owned(tx, deadline).await?;
                drop(client);
                return Ok(([(header::CACHE_CONTROL, "no-store")], Json(body)).into_response());
            }
            return Err(Error(StatusCode::CONFLICT, "job already has a different target or state"));
        }
        producer
            .roots
            .register_serving_in_tx(
                &tx,
                prepared.request.candidate(),
                prepared.request.request_id(),
                prepared.request.digest(),
                deadline,
            )
            .await
            .map_err(root_error)?;
        producer
            .roots
            .recheck_serving_source_pin_live_in_tx(&tx, &prepared.snapshot, deadline)
            .await
            .map_err(root_error)?;
        tx.execute(
            "INSERT INTO s4_ci_retention.ci_pins \
             (repository_id, job_id, owner_tenant_id, issuer_actor_id, issuer_token_id, \
              storage_generation, authority_epoch, history_incarnation, group_epoch, object_format, \
              target_oid, retention_root_id, register_digest_hex, pack_set_digest_hex, state) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'pinned')",
            &[
                &repository_id,
                &input.job_id,
                &tenant_id,
                &actor.id,
                &actor.token_id,
                &input.storage_generation,
                &serving.gate.authority_epoch(),
                &serving.gate.history_incarnation(),
                &serving.gate.group_epoch(),
                &format,
                &target_oid,
                &root_id,
                &register_digest,
                &pack_set_digest,
            ],
        )
        .await
        .map_err(Error::internal)?;
        commit_owned(tx, deadline).await?;
        drop(client);
        Ok((
            [(header::CACHE_CONTROL, "no-store")],
            Json(S4PinView {
                job_id: input.job_id,
                repository_id,
                object_format: format.clone(),
                target_oid: target_oid.to_owned(),
                storage_generation: input.storage_generation,
                retention_root_id: root_id,
                register_digest: register_digest.clone(),
                pack_set_digest: pack_set_digest.clone(),
                state: "pinned",
            }),
        )
            .into_response())
    }
    .await;
    // The transient verification pin is released on success *and* on every
    // refusal, so a refused registration cannot consume the 64-pin A5a quota.
    producer.release_source_snapshot(&state.pool, snapshot_scope, &source_snapshot, deadline).await;
    outcome
}
