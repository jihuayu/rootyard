//! Authorized serving coordinator for durable A5a snapshot metadata.
//!
//! This is the narrow serving entry point over the existing
//! `ref_store_core_snapshots`/pins/receipts/history/quota path. It adds no
//! migration, table, HTTP route or root API. It also owns the narrow authorized
//! retained-serving materialization entrypoint: T1 authorization/capture, actual
//! Blob/native closure outside every PG lease, then a fresh authorized T2
//! recheck and exact post-I/O metadata comparison. The caller supplies only a
//! repository selector, a bounded opaque idempotency key, a bounded
//! lease/generation and (for read/renew/release/materialize) a snapshot
//! selector. All repository/tenant/owner/realm/backend/gate facts are derived
//! from the real ready binding and current core gate.
//!
//! Every successful fresh or replay result passes the final
//! `authorize_repository_late` check on the same transaction that owns the
//! mutation/receipt and holds the token row `FOR SHARE` until acknowledged
//! commit (or read rollback). A plain preflight is only an early filter.
//!
//! Stable ids are SHA-256 domain-separated from repository + authenticated
//! principal + action + opaque key. They never contain the gate revision or
//! lease, so a retry under the same key stays the same identity while changed
//! lease/selector/generation conflicts in the existing request digest.
use super::{
    acquire, begin_owned, deadline_error, map_refstore, map_scope_refusal,
    ServingRepository,
};
use crate::{
    Error, auth,
    blob_store::BlobBackendIdentity,
    db::Identity,
    members::models::Role,
    ref_store::{
        CoreGate, MetadataMutationAction, MetadataPinPurpose, PinReleaseReason, RefStoreError, RequestDigest,
        core::{
            CreatePackSnapshotRequest, MAX_PIN_LEASE_SECONDS, MaterializedPackRead, MetadataPinOutcome,
            MetadataSnapshotScope, PackReadSnapshot, PackSnapshotExpectation, PackSnapshotOutcome, PackSnapshotRef,
            PgPackSnapshot, PgPackSnapshotMaterializer, PgRefStoreCore, ReleaseMetadataPinRequest,
            RenewMetadataPinRequest,
            serving_scope::LockedScope,
        },
        tx::commit_bounded,
    },
    token_scopes::RepoAction,
};
use crate::ref_store::core::pack_snapshot::RetainedServingPreparation;
use axum::http::StatusCode;
use deadpool_postgres::Pool;
use std::time::Duration;
use tokio::time::{Instant, timeout_at};
use tokio_postgres::Transaction;
use uuid::Uuid;

const CREATE_REQUEST_DOMAIN: &str = "serving-durable-snapshot-create-request-v1";
const CREATE_SNAPSHOT_DOMAIN: &str = "serving-durable-snapshot-create-snapshot-v1";
const CREATE_PIN_DOMAIN: &str = "serving-durable-snapshot-create-pin-v1";
const RENEW_REQUEST_DOMAIN: &str = "serving-durable-snapshot-renew-request-v1";
const RELEASE_REQUEST_DOMAIN: &str = "serving-durable-snapshot-release-request-v1";
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 128;
const SERVING_PURPOSE: MetadataPinPurpose = MetadataPinPurpose::Verification;

/// Bounded create input. `owner`/`name` are route selectors, not authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServingSnapshotCreate {
    pub owner: String,
    pub name: String,
    pub idempotency_key: String,
    pub lease_seconds: i64,
}

/// Bounded read selector. The pin id/generation are reconstructed from rows.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServingSnapshotRead {
    pub owner: String,
    pub name: String,
    pub snapshot_id: Uuid,
}

/// Bounded renew input. `expected_generation` is the existing CAS selector.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServingSnapshotRenew {
    pub owner: String,
    pub name: String,
    pub snapshot_id: Uuid,
    pub idempotency_key: String,
    pub expected_generation: i64,
    pub lease_seconds: i64,
}

/// Bounded release input. Release is one-way and exact-generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServingSnapshotRelease {
    pub owner: String,
    pub name: String,
    pub snapshot_id: Uuid,
    pub idempotency_key: String,
    pub expected_generation: i64,
    pub reason: PinReleaseReason,
}

/// Opaque retained materialization context for an HTTP content consumer. It
/// carries the exact T1 snapshot, cluster anchor and absolute deadline from the
/// one materialization call so a final post-encoding authorization/state fence
/// can revalidate the same capture. It is not a serving proof, is not Clone or
/// Serialize, and has no public constructor or capability.
pub(crate) struct RetainedServingReadContext {
    view: MaterializedPackRead,
    cluster_incarnation: Uuid,
    deadline: Instant,
}

impl RetainedServingReadContext {
    pub(crate) fn view(&self) -> &MaterializedPackRead {
        &self.view
    }

    pub(crate) fn deadline(&self) -> Instant {
        self.deadline
    }

    fn into_view(self) -> MaterializedPackRead {
        self.view
    }
}

/// Stateless coordinator. It owns the short bounded transaction and the final
/// late token check; the core adapters own the existing SQL/ledger details.
#[derive(Clone, Copy, Debug, Default)]
pub struct PgServingSnapshotMetadata;

impl PgServingSnapshotMetadata {
    /// Capture one durable serving pack snapshot through the existing A5a
    /// create/replay/quota/history path. A fresh capture uses the current gate;
    /// an exact retry reconstructs the original gate expectation from the
    /// stored receipt/header before its digest is checked.
    pub async fn create(
        &self,
        pool: &Pool,
        actor: &Identity,
        input: ServingSnapshotCreate,
        backend: &BlobBackendIdentity,
        deadline: Instant,
    ) -> Result<PackSnapshotOutcome, Error> {
        validate_key(&input.idempotency_key)?;
        validate_lease(input.lease_seconds)?;
        let preflight = preflight(pool, actor, &input.owner, &input.name, true, backend, deadline).await?;
        let repository_id = preflight.repository.id;
        let scope = scope_from_gate(&preflight.gate)?;
        let request_id = derived_uuid(
            CREATE_REQUEST_DOMAIN,
            repository_id,
            actor.id,
            "create",
            &input.idempotency_key,
        );
        let snapshot_id = derived_uuid(
            CREATE_SNAPSHOT_DOMAIN,
            repository_id,
            actor.id,
            "create",
            &input.idempotency_key,
        );
        let pin_id = derived_uuid(CREATE_PIN_DOMAIN, repository_id, actor.id, "create", &input.idempotency_key);

        let mut client = acquire(pool, deadline).await?;
        let tx = begin_owned(&mut client, deadline).await?;
        let core = async {
            // Request advisory first, then the lock-free replay pre-read and
            // the existing create adapter. This is the frozen request -> quota
            // -> repository/gate -> pin -> receipt direction.
            PgPackSnapshot.serving_request_lock(&tx, request_id, deadline).await?;
            let expected = match PgPackSnapshot
                .serving_create_expectation(&tx, &scope, request_id, pin_id, snapshot_id, deadline)
                .await?
            {
                Some(expected) => expected,
                None => PackSnapshotExpectation::new(preflight.gate.revision(), *preflight.gate.digest())
                    .map_err(|_| request_construction_error())?,
            };
            let request = CreatePackSnapshotRequest::new(
                scope,
                request_id,
                pin_id,
                snapshot_id,
                input.lease_seconds,
                expected,
            )
            .map_err(|_| request_construction_error())?;
            PgPackSnapshot
                .create_serving_checked(&tx, &request, backend.as_hex(), deadline)
                .await
        }
        .await;
        match core {
            Ok(outcome) => {
                match final_authority(
                    &tx,
                    actor,
                    repository_id,
                    scope.tenant_id(),
                    &preflight.repository.name,
                    RepoAction::ContentsWrite,
                    backend,
                    Some(&scope),
                    true,
                    deadline,
                )
                .await
                {
                    Ok(_) => {
                        let committed = commit_bounded(tx, deadline, repository_id, None).await;
                        crate::ref_store::core::metadata_commit_result(
                            committed,
                            repository_id,
                            request_id,
                            pin_id,
                            MetadataMutationAction::Create,
                        )
                        .map_err(map_metadata_error)?;
                        Ok(outcome)
                    }
                    Err(error) => {
                        rollback_bounded(tx).await;
                        Err(error)
                    }
                }
            }
            Err(error) => {
                let surface = authorize_failure(
                    &tx,
                    actor,
                    repository_id,
                    scope.tenant_id(),
                    &preflight.repository.name,
                    RepoAction::ContentsWrite,
                    backend,
                    Some(&scope),
                    true,
                    error,
                    deadline,
                )
                .await;
                rollback_bounded(tx).await;
                Err(surface)
            }
        }
    }

    /// Read one durable serving snapshot by its authorized repository-scoped
    /// selector. The pin/generation come from stored rows; a historical gate
    /// revision is allowed after refs advance as long as the current realm and
    /// serving binding still match.
    pub async fn read(
        &self,
        pool: &Pool,
        actor: &Identity,
        input: ServingSnapshotRead,
        backend: &BlobBackendIdentity,
        deadline: Instant,
    ) -> Result<PackReadSnapshot, Error> {
        validate_snapshot(input.snapshot_id)?;
        let preflight = preflight(pool, actor, &input.owner, &input.name, false, backend, deadline).await?;
        let repository_id = preflight.repository.id;
        let tenant_id = preflight.gate.tenant_id();
        let mut client = acquire(pool, deadline).await?;
        let tx = begin_owned(&mut client, deadline).await?;
        let result = async {
            // Current Admin is checked before any target-sensitive row read.
            // The final late ContentsRead check follows the pin/gate locks and
            // also runs on semantic read errors before their state is surfaced.
            serving_admin_gate(
                &tx,
                actor,
                repository_id,
                tenant_id,
                &preflight.repository.name,
                backend,
                None,
                false,
                deadline,
            )
            .await?;
            let value = match PgPackSnapshot
                .read_serving_by_snapshot(
                    &tx,
                    repository_id,
                    tenant_id,
                    input.snapshot_id,
                    backend.as_hex(),
                    deadline,
                )
                .await
            {
                Ok(value) => value,
                Err(error) => {
                    return Err(authorize_failure(
                        &tx,
                        actor,
                        repository_id,
                        tenant_id,
                        &preflight.repository.name,
                        RepoAction::ContentsRead,
                        backend,
                        None,
                        false,
                        error,
                        deadline,
                    )
                    .await);
                }
            };
            final_authority(
                &tx,
                actor,
                repository_id,
                tenant_id,
                &preflight.repository.name,
                RepoAction::ContentsRead,
                backend,
                None,
                false,
                deadline,
            )
            .await?;
            Ok::<PackReadSnapshot, Error>(value)
        }
        .await;
        rollback_bounded(tx).await;
        result
    }

    /// Materialize one retained durable serving snapshot through the actual
    /// opened Blob store and trusted native Git engine.
    ///
    /// The caller supplies only owner/name/snapshot selectors. T1 resolves the
    /// exact stored pin/generation/realm/backend from PostgreSQL and requires
    /// current Admin plus late ContentsRead; native/Blob closure runs outside
    /// every PG lease; T2 is a fresh authorized read transaction that rechecks
    /// the same stored capture, cluster anchor, pin liveness and role/scope
    /// before an unanchored materialized view may be returned.
    pub async fn materialize(
        &self,
        pool: &Pool,
        actor: &Identity,
        input: ServingSnapshotRead,
        materializer: &PgPackSnapshotMaterializer,
        deadline: Instant,
    ) -> Result<MaterializedPackRead, Error> {
        Ok(self.materialize_with_context(pool, actor, input, materializer, deadline).await?.into_view())
    }

    /// Internal same-flow form that retains the exact T1 capture, cluster anchor
    /// and effective absolute deadline until the caller's post-encoding final
    /// fence. The public [`Self::materialize`] API unwraps the view exactly as
    /// before.
    pub(crate) async fn materialize_with_context(
        &self,
        pool: &Pool,
        actor: &Identity,
        input: ServingSnapshotRead,
        materializer: &PgPackSnapshotMaterializer,
        deadline: Instant,
    ) -> Result<RetainedServingReadContext, Error> {
        validate_snapshot(input.snapshot_id)?;
        let deadline = materializer.retained_deadline(deadline).map_err(map_metadata_error)?;
        let backend = materializer.backend_identity();
        let initial = match timeout_at(
            deadline,
            preflight(pool, actor, &input.owner, &input.name, false, backend, deadline),
        )
        .await
        {
            Ok(result) => result?,
            Err(_) => return Err(deadline_error()),
        };
        let repository_id = initial.repository.id;
        let tenant_id = initial.gate.tenant_id();
        let name = initial.repository.name.clone();

        let (snapshot, cluster_incarnation) =
            retained_t1(pool, actor, repository_id, tenant_id, &name, input.snapshot_id, backend, deadline)
                .await?;
        let reference = PackSnapshotRef::new(
            repository_id,
            tenant_id,
            snapshot.snapshot_id(),
            snapshot.pin_id(),
            snapshot.pin_generation(),
        )
        .map_err(map_metadata_error)?;
        let prepared = match timeout_at(
            deadline,
            materializer.prepare_retained_serving(snapshot, cluster_incarnation, deadline),
        )
        .await
        {
            Ok(result) => result.map_err(map_metadata_error)?,
            Err(_) => return Err(deadline_error()),
        };
        let view = retained_t2(
            pool,
            actor,
            repository_id,
            tenant_id,
            &name,
            &reference,
            prepared,
            materializer,
            backend,
            deadline,
        )
        .await?;
        Ok(RetainedServingReadContext { view, cluster_incarnation, deadline })
    }

    /// Strict final fence for a retained HTTP content read: after the caller has
    /// fully read content and encoded its bounded JSON body, re-derive the same
    /// authorized repository and re-read the exact stored capture in one fresh
    /// transaction. Current Admin/ContentsRead, ready binding/backend/gate,
    /// T1 cluster anchor and fresh pin liveness must all still match. The value
    /// is returned only when that transaction's bounded rollback succeeds.
    pub(crate) async fn finalize_materialized(
        &self,
        pool: &Pool,
        actor: &Identity,
        input: &ServingSnapshotRead,
        context: RetainedServingReadContext,
        materializer: &PgPackSnapshotMaterializer,
    ) -> Result<MaterializedPackRead, Error> {
        validate_snapshot(input.snapshot_id)?;
        let deadline = context.deadline;
        let backend = materializer.backend_identity();
        let initial = match timeout_at(
            deadline,
            preflight(pool, actor, &input.owner, &input.name, false, backend, deadline),
        )
        .await
        {
            Ok(result) => result?,
            Err(_) => return Err(deadline_error()),
        };
        let view = context.view();
        if input.snapshot_id != view.snapshot_id()
            || initial.repository.id != view.repository_id()
            || initial.gate.tenant_id() != view.tenant_id()
        {
            return Err(Error(StatusCode::CONFLICT, "snapshot metadata scope changed"));
        }
        let reference = PackSnapshotRef::new(
            view.repository_id(),
            view.tenant_id(),
            view.snapshot_id(),
            view.pin_id(),
            view.pin_generation(),
        )
        .map_err(map_metadata_error)?;
        retained_finalize_context(
            pool,
            actor,
            initial.repository.id,
            initial.gate.tenant_id(),
            &initial.repository.name,
            &reference,
            context,
            materializer,
            backend,
            deadline,
        )
        .await
    }

    /// Renew the stored pin at its exact generation. The stored scope and pin
    /// id are reconstructed from immutable rows; changed generation/lease under
    /// the same key conflicts in the existing request digest.
    pub async fn renew(
        &self,
        pool: &Pool,
        actor: &Identity,
        input: ServingSnapshotRenew,
        backend: &BlobBackendIdentity,
        deadline: Instant,
    ) -> Result<MetadataPinOutcome, Error> {
        validate_key(&input.idempotency_key)?;
        validate_snapshot(input.snapshot_id)?;
        validate_generation(input.expected_generation)?;
        validate_lease(input.lease_seconds)?;
        let preflight = preflight(pool, actor, &input.owner, &input.name, true, backend, deadline).await?;
        let repository_id = preflight.repository.id;
        let tenant_id = preflight.gate.tenant_id();
        let current_scope = scope_from_gate(&preflight.gate)?;
        let request_id = derived_uuid(
            RENEW_REQUEST_DOMAIN,
            repository_id,
            actor.id,
            "renew",
            &input.idempotency_key,
        );

        let mut client = acquire(pool, deadline).await?;
        let tx = begin_owned(&mut client, deadline).await?;
        let core = async {
            PgPackSnapshot.serving_request_lock(&tx, request_id, deadline).await?;
            let Some(identity) = PgPackSnapshot
                .serving_snapshot_identity(&tx, repository_id, tenant_id, input.snapshot_id, deadline)
                .await?
            else {
                return Err(RefStoreError::MetadataSnapshotNotFound { snapshot_id: input.snapshot_id });
            };
            let request = RenewMetadataPinRequest::new(
                identity.scope,
                request_id,
                identity.pin_id,
                input.expected_generation,
                input.lease_seconds,
            )
            .map_err(|_| request_construction_error())?;
            let outcome = PgRefStoreCore
                .renew_serving_checked(&tx, &request, backend.as_hex(), deadline)
                .await?;
            Ok::<(MetadataPinOutcome, Uuid), RefStoreError>((outcome, identity.pin_id))
        }
        .await;
        match core {
            Ok((outcome, pin_id)) => {
                match final_authority(
                    &tx,
                    actor,
                    repository_id,
                    tenant_id,
                    &preflight.repository.name,
                    RepoAction::ContentsWrite,
                    backend,
                    Some(&current_scope),
                    false,
                    deadline,
                )
                .await
                {
                    Ok(_) => {
                        let committed = commit_bounded(tx, deadline, repository_id, None).await;
                        crate::ref_store::core::metadata_commit_result(
                            committed,
                            repository_id,
                            request_id,
                            pin_id,
                            MetadataMutationAction::Renew,
                        )
                        .map_err(map_metadata_error)?;
                        Ok(outcome)
                    }
                    Err(error) => {
                        rollback_bounded(tx).await;
                        Err(error)
                    }
                }
            }
            Err(error) => {
                let surface = authorize_failure(
                    &tx,
                    actor,
                    repository_id,
                    tenant_id,
                    &preflight.repository.name,
                    RepoAction::ContentsWrite,
                    backend,
                    Some(&current_scope),
                    false,
                    error,
                    deadline,
                )
                .await;
                rollback_bounded(tx).await;
                Err(surface)
            }
        }
    }

    /// Release the stored pin at its exact generation. The immutable receipt is
    /// returned only after acknowledged commit; an exact retry never extends or
    /// revives the lease.
    pub async fn release(
        &self,
        pool: &Pool,
        actor: &Identity,
        input: ServingSnapshotRelease,
        backend: &BlobBackendIdentity,
        deadline: Instant,
    ) -> Result<MetadataPinOutcome, Error> {
        validate_key(&input.idempotency_key)?;
        validate_snapshot(input.snapshot_id)?;
        validate_generation(input.expected_generation)?;
        let preflight = preflight(pool, actor, &input.owner, &input.name, true, backend, deadline).await?;
        let repository_id = preflight.repository.id;
        let tenant_id = preflight.gate.tenant_id();
        let current_scope = scope_from_gate(&preflight.gate)?;
        let request_id = derived_uuid(
            RELEASE_REQUEST_DOMAIN,
            repository_id,
            actor.id,
            "release",
            &input.idempotency_key,
        );

        let mut client = acquire(pool, deadline).await?;
        let tx = begin_owned(&mut client, deadline).await?;
        let core = async {
            PgPackSnapshot.serving_request_lock(&tx, request_id, deadline).await?;
            let Some(identity) = PgPackSnapshot
                .serving_snapshot_identity(&tx, repository_id, tenant_id, input.snapshot_id, deadline)
                .await?
            else {
                return Err(RefStoreError::MetadataSnapshotNotFound { snapshot_id: input.snapshot_id });
            };
            let request = ReleaseMetadataPinRequest::new(
                identity.scope,
                request_id,
                identity.pin_id,
                input.expected_generation,
                input.reason,
            )
            .map_err(|_| request_construction_error())?;
            let outcome = PgRefStoreCore
                .release_serving_checked(&tx, &request, backend.as_hex(), deadline)
                .await?;
            Ok::<(MetadataPinOutcome, Uuid), RefStoreError>((outcome, identity.pin_id))
        }
        .await;
        match core {
            Ok((outcome, pin_id)) => {
                match final_authority(
                    &tx,
                    actor,
                    repository_id,
                    tenant_id,
                    &preflight.repository.name,
                    RepoAction::ContentsWrite,
                    backend,
                    Some(&current_scope),
                    false,
                    deadline,
                )
                .await
                {
                    Ok(_) => {
                        let committed = commit_bounded(tx, deadline, repository_id, None).await;
                        crate::ref_store::core::metadata_commit_result(
                            committed,
                            repository_id,
                            request_id,
                            pin_id,
                            MetadataMutationAction::Release,
                        )
                        .map_err(map_metadata_error)?;
                        Ok(outcome)
                    }
                    Err(error) => {
                        rollback_bounded(tx).await;
                        Err(error)
                    }
                }
            }
            Err(error) => {
                let surface = authorize_failure(
                    &tx,
                    actor,
                    repository_id,
                    tenant_id,
                    &preflight.repository.name,
                    RepoAction::ContentsWrite,
                    backend,
                    Some(&current_scope),
                    false,
                    error,
                    deadline,
                )
                .await;
                rollback_bounded(tx).await;
                Err(surface)
            }
        }
    }
}

async fn preflight(
    pool: &Pool,
    actor: &Identity,
    owner: &str,
    name: &str,
    writable: bool,
    backend: &BlobBackendIdentity,
    deadline: Instant,
) -> Result<ServingRepository, Error> {
    super::lookup(pool, actor, owner, name, writable, backend, deadline).await
}

/// One checked T1 read transaction for retained materialization. The whole
/// authorization + target read + final late scope check is bounded by the
/// caller's absolute deadline, and a failed/expired rollback yields no capture.
#[allow(clippy::too_many_arguments)]
async fn retained_t1(
    pool: &Pool,
    actor: &Identity,
    repository_id: Uuid,
    tenant_id: Uuid,
    name: &str,
    snapshot_id: Uuid,
    backend: &BlobBackendIdentity,
    deadline: Instant,
) -> Result<(PackReadSnapshot, Uuid), Error> {
    let mut client = acquire(pool, deadline).await?;
    let tx = begin_owned(&mut client, deadline).await?;
    let observed = timeout_at(
        deadline,
        async {
            serving_admin_gate(
                &tx,
                actor,
                repository_id,
                tenant_id,
                name,
                backend,
                None,
                false,
                deadline,
            )
            .await?;
            let snapshot = match PgPackSnapshot
                .read_serving_by_snapshot(
                    &tx,
                    repository_id,
                    tenant_id,
                    snapshot_id,
                    backend.as_hex(),
                    deadline,
                )
                .await
            {
                Ok(snapshot) => snapshot,
                Err(error) => {
                    return Err(authorize_failure(
                        &tx,
                        actor,
                        repository_id,
                        tenant_id,
                        name,
                        RepoAction::ContentsRead,
                        backend,
                        None,
                        false,
                        error,
                        deadline,
                    )
                    .await);
                }
            };
            let (_, cluster_incarnation) = final_authority_with_cluster(
                &tx,
                actor,
                repository_id,
                tenant_id,
                name,
                RepoAction::ContentsRead,
                backend,
                Some(snapshot.scope()),
                false,
                deadline,
            )
            .await?;
            Ok::<_, Error>((snapshot, cluster_incarnation))
        },
    )
    .await;
    let observed = match observed {
        Ok(result) => result,
        Err(_) => Err(deadline_error()),
    };
    let cleanup = timeout_at(deadline, tx.rollback()).await;
    match (observed, cleanup) {
        (Ok(value), Ok(Ok(()))) => Ok(value),
        (_, Ok(Err(_))) | (_, Err(_)) => Err(retained_cleanup_error()),
        (Err(error), Ok(Ok(()))) => Err(error),
    }
}

/// One checked T2 transaction after native/Blob work: current Admin + late
/// ContentsRead, exact authorized stored capture, captured cluster anchor,
/// fresh DB-clock pin liveness, then the unanchored materialized view. No value
/// exists unless rollback succeeds.
#[allow(clippy::too_many_arguments)]
async fn retained_t2(
    pool: &Pool,
    actor: &Identity,
    repository_id: Uuid,
    tenant_id: Uuid,
    name: &str,
    reference: &PackSnapshotRef,
    prepared: RetainedServingPreparation,
    materializer: &PgPackSnapshotMaterializer,
    backend: &BlobBackendIdentity,
    deadline: Instant,
) -> Result<MaterializedPackRead, Error> {
    let mut client = acquire(pool, deadline).await?;
    let tx = begin_owned(&mut client, deadline).await?;
    let observed = timeout_at(
        deadline,
        async {
            let expected_scope = *prepared.snapshot().scope();
            serving_admin_gate(
                &tx,
                actor,
                repository_id,
                tenant_id,
                name,
                backend,
                Some(&expected_scope),
                false,
                deadline,
            )
            .await?;
            let fresh = match PgPackSnapshot
                .read_serving_by_snapshot(
                    &tx,
                    repository_id,
                    tenant_id,
                    reference.snapshot_id(),
                    backend.as_hex(),
                    deadline,
                )
                .await
            {
                Ok(snapshot) => snapshot,
                Err(error) => {
                    return Err(authorize_failure(
                        &tx,
                        actor,
                        repository_id,
                        tenant_id,
                        name,
                        RepoAction::ContentsRead,
                        backend,
                        Some(&expected_scope),
                        false,
                        error,
                        deadline,
                    )
                    .await);
                }
            };
            let (_, cluster_incarnation) = final_authority_with_cluster(
                &tx,
                actor,
                repository_id,
                tenant_id,
                name,
                RepoAction::ContentsRead,
                backend,
                Some(&expected_scope),
                false,
                deadline,
            )
            .await?;
            if cluster_incarnation != prepared.cluster_incarnation() {
                return Err(map_metadata_error(RefStoreError::MetadataScopeMismatch(
                    "cluster authority incarnation",
                )));
            }
            materializer
                .ensure_retained_serving_live(&tx, reference, &fresh, deadline)
                .await
                .map_err(map_metadata_error)?;
            prepared.finish(fresh).map_err(map_metadata_error)
        },
    )
    .await;
    let observed = match observed {
        Ok(result) => result,
        Err(_) => Err(deadline_error()),
    };
    let cleanup = timeout_at(deadline, tx.rollback()).await;
    match (observed, cleanup) {
        (Ok(view), Ok(Ok(()))) => Ok(view),
        (_, Ok(Err(_))) | (_, Err(_)) => Err(retained_cleanup_error()),
        (Err(error), Ok(Ok(()))) => Err(error),
    }
}

/// Final post-encoding fence for an already materialized retained view. It
/// reuses the same fresh authorized read and pin-liveness checks as T2 but does
/// not re-run native work or construct a second view.
#[allow(clippy::too_many_arguments)]
async fn retained_finalize_context(
    pool: &Pool,
    actor: &Identity,
    repository_id: Uuid,
    tenant_id: Uuid,
    name: &str,
    reference: &PackSnapshotRef,
    context: RetainedServingReadContext,
    materializer: &PgPackSnapshotMaterializer,
    backend: &BlobBackendIdentity,
    deadline: Instant,
) -> Result<MaterializedPackRead, Error> {
    let RetainedServingReadContext { view, cluster_incarnation, .. } = context;
    let mut client = acquire(pool, deadline).await?;
    let tx = begin_owned(&mut client, deadline).await?;
    let observed = timeout_at(
        deadline,
        async {
            let expected_scope = *view.snapshot().scope();
            serving_admin_gate(
                &tx,
                actor,
                repository_id,
                tenant_id,
                name,
                backend,
                Some(&expected_scope),
                false,
                deadline,
            )
            .await?;
            let fresh = match PgPackSnapshot
                .read_serving_by_snapshot(
                    &tx,
                    repository_id,
                    tenant_id,
                    reference.snapshot_id(),
                    backend.as_hex(),
                    deadline,
                )
                .await
            {
                Ok(snapshot) => snapshot,
                Err(error) => {
                    return Err(authorize_failure(
                        &tx,
                        actor,
                        repository_id,
                        tenant_id,
                        name,
                        RepoAction::ContentsRead,
                        backend,
                        Some(&expected_scope),
                        false,
                        error,
                        deadline,
                    )
                    .await);
                }
            };
            let (_, current_cluster) = final_authority_with_cluster(
                &tx,
                actor,
                repository_id,
                tenant_id,
                name,
                RepoAction::ContentsRead,
                backend,
                Some(&expected_scope),
                false,
                deadline,
            )
            .await?;
            if current_cluster != cluster_incarnation {
                return Err(map_metadata_error(RefStoreError::MetadataScopeMismatch(
                    "cluster authority incarnation",
                )));
            }
            materializer
                .ensure_retained_serving_live(&tx, reference, &fresh, deadline)
                .await
                .map_err(map_metadata_error)?;
            if fresh != *view.snapshot() {
                return Err(map_metadata_error(RefStoreError::MetadataScopeMismatch(
                    "retained serving snapshot",
                )));
            }
            if fresh.materialization_digest() != view.proven_binding() {
                return Err(map_metadata_error(RefStoreError::MetadataScopeMismatch(
                    "retained serving binding",
                )));
            }
            Ok(view)
        },
    )
    .await;
    let observed = match observed {
        Ok(result) => result,
        Err(_) => Err(deadline_error()),
    };
    let cleanup = timeout_at(deadline, tx.rollback()).await;
    match (observed, cleanup) {
        (Ok(view), Ok(Ok(()))) => Ok(view),
        (_, Ok(Err(_))) | (_, Err(_)) => Err(retained_cleanup_error()),
        (Err(error), Ok(Ok(()))) => Err(error),
    }
}

fn retained_cleanup_error() -> Error {
    Error(StatusCode::SERVICE_UNAVAILABLE, "retained snapshot metadata cleanup failed")
}

pub(super) async fn serving_admin_gate(
    tx: &Transaction<'_>,
    actor: &Identity,
    repository_id: Uuid,
    tenant_id: Uuid,
    name: &str,
    backend: &BlobBackendIdentity,
    expected_scope: Option<&MetadataSnapshotScope>,
    gate_for_update: bool,
    deadline: Instant,
) -> Result<CoreGate, Error> {
    crate::ref_store::pg::bound(tx, deadline).await.map_err(map_metadata_error)?;
    let locked = LockedScope::lock(tx, repository_id, false)
        .await
        .map_err(map_metadata_error)?
        .ok_or_else(Error::not_found)?;
    if locked.owner_id() != tenant_id || locked.name() != name {
        return Err(Error::not_found());
    }
    // Current actor permission is checked before any serving-backend/gate/realm
    // or snapshot-specific refusal can surface. A non-admin must not learn a
    // target's shape from an earlier state-specific error path.
    let Some((role, _, _)) =
        crate::members::rbac::resolve_effective_role(tx, repository_id, tenant_id, actor.id)
            .await
            .map_err(Error::internal)?
    else {
        return Err(Error::not_found());
    };
    if role < Role::Admin {
        return Err(Error(StatusCode::FORBIDDEN, "insufficient repository role"));
    }
    let binding = locked
        .require_serving(tenant_id, backend.as_hex())
        .map_err(map_scope_refusal)?;
    let gate = PgRefStoreCore
        .read_gate_in_tx(tx, repository_id, gate_for_update)
        .await
        .map_err(map_metadata_error)?
        .ok_or_else(Error::not_found)?;
    locked.require_binding_matches_gate(&gate).map_err(map_scope_refusal)?;
    if gate.repository_id() != repository_id
        || gate.tenant_id() != tenant_id
        || gate.object_format() != binding.object_format()
    {
        return Err(Error::internal("durable serving gate/binding realm mismatch"));
    }
    if let Some(scope) = expected_scope {
        if gate.tenant_id() != scope.tenant_id()
            || gate.object_format() != scope.object_format()
            || gate.history_incarnation() != scope.history_incarnation()
            || gate.authority_epoch() != scope.authority_epoch()
            || gate.group_epoch() != scope.group_epoch()
        {
            return Err(Error(StatusCode::CONFLICT, "repository realm changed; retry the same request"));
        }
    }
    Ok(gate)
}

async fn final_authority(
    tx: &Transaction<'_>,
    actor: &Identity,
    repository_id: Uuid,
    tenant_id: Uuid,
    name: &str,
    action: RepoAction,
    backend: &BlobBackendIdentity,
    expected_scope: Option<&MetadataSnapshotScope>,
    gate_for_update: bool,
    deadline: Instant,
) -> Result<CoreGate, Error> {
    final_authority_with_cluster(
        tx,
        actor,
        repository_id,
        tenant_id,
        name,
        action,
        backend,
        expected_scope,
        gate_for_update,
        deadline,
    )
    .await
    .map(|(gate, _)| gate)
}

pub(super) async fn final_authority_with_cluster(
    tx: &Transaction<'_>,
    actor: &Identity,
    repository_id: Uuid,
    tenant_id: Uuid,
    name: &str,
    action: RepoAction,
    backend: &BlobBackendIdentity,
    expected_scope: Option<&MetadataSnapshotScope>,
    gate_for_update: bool,
    deadline: Instant,
) -> Result<(CoreGate, Uuid), Error> {
    let gate = serving_admin_gate(
        tx,
        actor,
        repository_id,
        tenant_id,
        name,
        backend,
        expected_scope,
        gate_for_update,
        deadline,
    )
    .await?;
    let cluster_incarnation = super::authority::cluster_incarnation_nowait(tx).await?;
    let live = tx
        .query_opt(
            "SELECT t.read_only FROM tokens t
             WHERE t.id=$1 AND t.user_id=$2 AND t.digest=$3 AND NOT t.revoked
               AND (t.expires_at IS NULL OR t.expires_at > clock_timestamp()) AND t.kind='api'",
            &[&actor.token_id, &actor.id, &actor.token_digest],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::unauthorized)?;
    let _read_only: bool = live.get(0);
    crate::token_scopes::authorize_repository_late(
        tx,
        actor.token_id,
        actor.id,
        repository_id,
        action,
        false,
    )
    .await
    .map_err(auth::scope_error)?;
    Ok((gate, cluster_incarnation))
}

fn request_construction_error() -> RefStoreError {
    RefStoreError::Database("snapshot metadata request could not be constructed".into())
}

/// Run the required current Admin + same-final-transaction late scope check
/// before surfacing a target-sensitive semantic failure. Authorized callers keep
/// the original error semantics; denied callers get the authorization error, so
/// target existence/generation/release/replay state is not an oracle.
#[allow(clippy::too_many_arguments)]
async fn authorize_failure(
    tx: &Transaction<'_>,
    actor: &Identity,
    repository_id: Uuid,
    tenant_id: Uuid,
    name: &str,
    action: RepoAction,
    backend: &BlobBackendIdentity,
    expected_scope: Option<&MetadataSnapshotScope>,
    gate_for_update: bool,
    error: RefStoreError,
    deadline: Instant,
) -> Error {
    // Always attempt the authoritative final check. A healthy transaction runs
    // current Admin + late scope and then returns the original authorized
    // semantic error; an aborted/deadline/unavailable transaction makes this
    // check fail closed with the opaque shared mapping instead of echoing an old
    // target-specific error.
    match final_authority(
        tx,
        actor,
        repository_id,
        tenant_id,
        name,
        action,
        backend,
        expected_scope,
        gate_for_update,
        deadline,
    )
    .await
    {
        Ok(_) => map_metadata_error(error),
        Err(auth_error) => auth_error,
    }
}

fn scope_from_gate(gate: &CoreGate) -> Result<MetadataSnapshotScope, Error> {
    MetadataSnapshotScope::new(
        gate.repository_id(),
        gate.tenant_id(),
        gate.tenant_id(),
        SERVING_PURPOSE,
        gate.object_format(),
        gate.history_incarnation(),
        gate.authority_epoch(),
        gate.group_epoch(),
    )
    .map_err(map_metadata_error)
}

fn derived_uuid(domain: &str, repository_id: Uuid, actor_id: Uuid, action: &str, key: &str) -> Uuid {
    let digest = RequestDigest::of(
        domain,
        &[repository_id.as_bytes(), actor_id.as_bytes(), action.as_bytes(), key.as_bytes()],
    );
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    // RFC 4122 version/variant bits keep these valid non-nil UUIDs without
    // changing the deterministic domain-separated payload.
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn validate_key(value: &str) -> Result<(), Error> {
    if value.is_empty()
        || value.len() > MAX_IDEMPOTENCY_KEY_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~'))
    {
        return Err(Error::bad_request());
    }
    Ok(())
}

fn validate_lease(value: i64) -> Result<(), Error> {
    if value <= 0 || value > MAX_PIN_LEASE_SECONDS {
        return Err(Error::bad_request());
    }
    Ok(())
}

fn validate_generation(value: i64) -> Result<(), Error> {
    if value <= 0 {
        return Err(Error::bad_request());
    }
    Ok(())
}

fn validate_snapshot(value: Uuid) -> Result<(), Error> {
    if value.is_nil() {
        return Err(Error::bad_request());
    }
    Ok(())
}

fn map_metadata_error(error: RefStoreError) -> Error {
    match error {
        RefStoreError::MetadataPinGenerationMismatch { .. } => {
            Error(StatusCode::CONFLICT, "snapshot pin generation changed")
        }
        RefStoreError::MetadataPinExpired { .. } => Error(StatusCode::CONFLICT, "snapshot pin lease expired"),
        RefStoreError::MetadataPinReleased { .. } => Error(StatusCode::CONFLICT, "snapshot pin is released"),
        RefStoreError::MetadataSnapshotNotFound { .. } | RefStoreError::MetadataPinNotFound { .. } => {
            Error::not_found()
        }
        RefStoreError::MetadataScopeMismatch(_) => {
            Error(StatusCode::CONFLICT, "snapshot metadata scope changed")
        }
        RefStoreError::MetadataGateVersionMismatch => {
            Error(StatusCode::CONFLICT, "repository gate changed; retry the same request")
        }
        RefStoreError::MetadataQuotaExceeded { .. } => {
            Error(StatusCode::TOO_MANY_REQUESTS, "retained snapshot quota is exhausted")
        }
        RefStoreError::MetadataSnapshotTooLarge { .. } => {
            Error(StatusCode::PAYLOAD_TOO_LARGE, "snapshot metadata is too large")
        }
        RefStoreError::MetadataCommitUnknown { .. } => Error(
            StatusCode::SERVICE_UNAVAILABLE,
            "metadata commit outcome is unknown; retry the same request",
        ),
        other => map_refstore(other),
    }
}

async fn rollback_bounded(tx: Transaction<'_>) {
    let _ = tokio::time::timeout(Duration::from_secs(2), tx.rollback()).await;
}
