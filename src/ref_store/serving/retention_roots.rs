//! Authorized serving retention-root facade.
//!
//! This module is the narrow service boundary between current serving
//! authorization and the private core roots adapter. It accepts only bounded
//! repository/source selectors and opaque idempotency keys; every repository,
//! tenant, source pin, realm, backend, root/operation/request id, business intent
//! and digest is derived from authorized PostgreSQL rows and canonical core
//! helpers. No HTTP serialization, route, candidate exchange or digest input
//! exists here.
use std::str::FromStr;

use axum::http::StatusCode;
use deadpool_postgres::{Pool, Transaction};
use tokio::time::{Instant, timeout_at};
use uuid::Uuid;

use crate::{
    Error, auth,
    blob_store::BlobBackendIdentity,
    db::{self, Identity},
    members::models::Role,
    ref_store::{
        CoreGate, MetadataPinPurpose, RefStoreError, RequestDigest,
        core::{
            MetadataSnapshotScope, PgPackSnapshot, PgRefStoreCore,
            PackReadSnapshot, PackSnapshotRef,
            retention_root::{
                PgRetentionRoots, PrepareRootRequest, REGISTER_REQUEST_DIGEST_DOMAIN, ReleaseRootRequest,
                RootCandidate, RootError, RootPurpose, RootReadView, RootReceipt, RootRecord, RootRef, RootSelector,
                RootsScope,
            },
            serving_scope::LockedScope,
        },
    },
    token_scopes::RepoAction,
};

const ROOT_ID_DOMAIN: &str = "serving-root-id-v1";
const ROOT_OPERATION_DOMAIN: &str = "serving-root-operation-v1";
const ROOT_REGISTER_REQUEST_DOMAIN: &str = "serving-root-register-request-v1";
const ROOT_RELEASE_REQUEST_DOMAIN: &str = "serving-root-release-request-v1";
const ROOT_BUSINESS_INTENT_DOMAIN: &str = "serving-root-business-intent-v1";
const ROOT_RELEASE_INTENT_DOMAIN: &str = "serving-root-release-intent-v1";
const ROOT_IDEMPOTENCY_MAX: usize = 256;
const ROOT_REASON_MAX: usize = 256;
/// Placeholder business intent for a metadata/read authorization probe before a
/// retained record supplies its own realm. `RootsScope` only exposes its realm
/// through the metadata-scope adapter; this value never reaches a mutation.
const PLACEHOLDER_BUSINESS_INTENT: &str = "1111111111111111111111111111111111111111111111111111111111111111";

/// One bounded original create intent. The same value is accepted by
/// release-before-register so the server can derive the exact root id and
/// expected register digest without any client-supplied digest.
#[derive(Clone, Debug)]
pub struct ServingRootIntent {
    pub source_snapshot_id: Uuid,
    pub selector: RootSelector,
    pub purpose: RootPurpose,
    pub idempotency_key: String,
}

/// Authorized create input. All authority fields are repo/name selectors only.
#[derive(Clone, Debug)]
pub struct ServingRootCreate {
    pub owner: String,
    pub name: String,
    pub intent: ServingRootIntent,
}

/// One metadata/byte read selector. Historical roots keep their own retained
/// rows; no source pin or source snapshot is read for the byte path.
#[derive(Clone, Debug)]
pub struct ServingRootRead {
    pub owner: String,
    pub name: String,
    pub root_id: Uuid,
}

/// Release target. `Existing` names an already retained root. `Absent` carries
/// the bounded original create intent for a release-before-register tombstone;
/// the path root id must equal the server-derived id.
#[derive(Clone, Debug)]
pub enum ServingRootReleaseTarget {
    Existing { root_id: Uuid },
    Absent { root_id: Uuid, create: ServingRootIntent },
}

/// Authorized one-way release input.
#[derive(Clone, Debug)]
pub struct ServingRootRelease {
    pub owner: String,
    pub name: String,
    pub target: ServingRootReleaseTarget,
    pub idempotency_key: String,
    pub reason: String,
}

/// Opaque retained root read context for the future post-JSON authorization
/// fence. It holds the already-authorized view, its original T1 cluster anchor
/// and the one effective absolute deadline. It is not Clone, serde, a session,
/// an HWM, a #174 proof or a public constructor.
pub(crate) struct ServingRetainedRootReadContext {
    view: RootReadView,
    root: RootRef,
    repository_id: Uuid,
    tenant_id: Uuid,
    name: String,
    cluster_incarnation: Uuid,
    deadline: Instant,
}

impl ServingRetainedRootReadContext {
    pub(crate) fn view(&self) -> &RootReadView {
        &self.view
    }

    pub(crate) fn deadline(&self) -> Instant {
        self.deadline
    }

    fn into_view(self) -> RootReadView {
        self.view
    }
}

/// Authorized retention-root service facade over the actual opened
/// `PgRetentionRoots` engine/store. Construction grants no authority.
pub struct PgServingRetentionRoots {
    roots: PgRetentionRoots,
}

impl PgServingRetentionRoots {
    pub fn new(roots: PgRetentionRoots) -> Self {
        Self { roots }
    }

    fn backend(&self) -> &BlobBackendIdentity {
        self.roots.backend_identity()
    }

    /// Create one retained root as a single service operation: preflight current
    /// Admin+ContentsWrite, exact retained-root replay before any source lookup,
    /// authorized source read, native prepare outside PostgreSQL, then a fresh
    /// register transaction with final late auth/cluster/pin checks.
    pub async fn create(
        &self,
        pool: &Pool,
        actor: &Identity,
        input: ServingRootCreate,
        deadline: Instant,
    ) -> Result<RootReceipt, Error> {
        validate_owner_name(&input.owner, &input.name)?;
        validate_intent(&input.intent)?;
        let deadline = root_deadline(deadline)?;
        let repo = self
            .preflight(pool, actor, &input.owner, &input.name, RepoAction::ContentsWrite, deadline)
            .await?;
        let derived = derive_intent(&repo.gate, &input.intent)?;
        let scope = root_scope(&repo, input.intent.purpose, &derived.business_intent)?;

        // Exact create replay lives entirely on retained root/receipt rows and
        // runs before source pin/snapshot lookup or native work.
        if let Some(receipt) = self
            .replay_create(pool, actor, &repo, &scope, &input.intent, &derived, deadline)
            .await?
        {
            return Ok(receipt);
        }

        let source = self.source_snapshot(pool, actor, &repo, &scope, &input.intent, deadline).await?;
        let format = source.scope().object_format();
        if format != repo.gate.object_format()
            || source.scope().history_incarnation() != repo.gate.history_incarnation()
            || source.scope().authority_epoch() != repo.gate.authority_epoch()
            || source.scope().group_epoch() != repo.gate.group_epoch()
            || source.scope().tenant_id() != repo.tenant_id
            || source.scope().owner_id() != repo.tenant_id
        {
            return Err(Error(StatusCode::CONFLICT, "source snapshot realm changed; retry the same request"));
        }
        let reference = PackSnapshotRef::new(
            repo.repository_id,
            repo.tenant_id,
            source.snapshot_id(),
            source.pin_id(),
            source.pin_generation(),
        )
        .map_err(map_root_error)?;
        let request = PrepareRootRequest::new(
            scope,
            reference,
            derived.root_id,
            derived.operation_id,
            input.intent.selector.clone(),
            derived.register_request_id,
        )
        .map_err(map_root_error)?;
        let candidate = self.roots.prepare_serving(pool, request, deadline).await.map_err(map_root_error)?;
        if candidate.serving_cluster_incarnation().is_none() {
            return Err(Error::internal("serving root candidate has no cluster anchor"));
        }
        let reference = *candidate.reference();
        let expected_scope = *candidate.scope();
        let expected_cluster = candidate.serving_cluster_incarnation().ok_or_else(|| {
            Error::internal("serving root candidate lost its cluster anchor")
        })?;
        let request_digest = register_request_digest(&candidate, derived.register_request_id);

        let mut client = super::acquire(pool, deadline).await?;
        let tx = super::begin_owned(&mut client, deadline).await?;
        if let Err(error) = crate::ref_store::pg::bound(&tx, deadline).await.map_err(super::map_refstore) {
            let _cleanup = rollback_strict(tx, deadline).await;
            drop(client);
            return Err(error);
        }
        let outcome = timeout_at(deadline, async {
            let receipt = match self
                .roots
                .register_serving_in_tx(
                    &tx,
                    &candidate,
                    derived.register_request_id,
                    request_digest,
                    deadline,
                )
                .await
            {
                Ok(receipt) => receipt,
                Err(error) => {
                    return match final_authority_root(
                        &tx,
                        actor,
                        &repo,
                        RepoAction::ContentsWrite,
                        &expected_scope,
                        self.backend(),
                        None,
                        deadline,
                    )
                    .await
                    {
                        Ok(_) => Err(map_root_error(error)),
                        Err(auth_error) => Err(auth_error),
                    };
                }
            };
            final_authority_root(
                &tx,
                actor,
                &repo,
                RepoAction::ContentsWrite,
                &expected_scope,
                self.backend(),
                Some(expected_cluster),
                deadline,
            )
            .await?;
            self.roots
                .recheck_serving_source_pin_live_in_tx(&tx, &reference, deadline)
                .await
                .map_err(map_root_error)?;
            Ok::<RootReceipt, Error>(receipt)
        })
        .await;
        let outcome = match outcome {
            Ok(result) => result,
            Err(_) => Err(super::deadline_error()),
        };
        match outcome {
            Ok(receipt) => {
                super::commit_owned(tx, deadline).await?;
                Ok(receipt)
            }
            Err(error) => {
                let cleanup = rollback_strict(tx, deadline).await;
                drop(client);
                cleanup?;
                Err(error)
            }
        }
    }

    /// Authorized one-way release. Existing roots derive scope/register digest
    /// from retained rows and never read the source pin. Absent roots require the
    /// bounded original create intent and derive the expected register digest with
    /// the core canonical binding helper; no client digest or native candidate is
    /// accepted.
    pub async fn release(
        &self,
        pool: &Pool,
        actor: &Identity,
        input: ServingRootRelease,
        deadline: Instant,
    ) -> Result<RootReceipt, Error> {
        validate_owner_name(&input.owner, &input.name)?;
        validate_key(&input.idempotency_key)?;
        validate_reason(&input.reason)?;
        let deadline = root_deadline(deadline)?;
        let repo = self
            .preflight(pool, actor, &input.owner, &input.name, RepoAction::ContentsWrite, deadline)
            .await?;

        match input.target.clone() {
            ServingRootReleaseTarget::Existing { root_id } => {
                if root_id.is_nil() {
                    return Err(Error(::axum::http::StatusCode::BAD_REQUEST, "invalid root id"));
                }
                self.release_existing(pool, actor, &repo, root_id, &input, deadline).await
            }
            ServingRootReleaseTarget::Absent { root_id, create } => {
                validate_intent(&create)?;
                let derived = derive_intent(&repo.gate, &create)?;
                if derived.root_id != root_id {
                    return Err(Error::not_found());
                }
                let scope = root_scope(&repo, create.purpose, &derived.business_intent)?;
                self.release_absent(pool, actor, &repo, root_id, &create, &derived, &scope, &input, deadline).await
            }
        }
    }

    /// Internal data-only root record. The value is never HTTP-serialized here;
    /// callers in checkpoint 3 must project only safe fields.
    pub async fn metadata(
        &self,
        pool: &Pool,
        actor: &Identity,
        input: ServingRootRead,
        deadline: Instant,
    ) -> Result<Option<RootRecord>, Error> {
        validate_owner_name(&input.owner, &input.name)?;
        validate_root_id(input.root_id)?;
        let deadline = root_deadline(deadline)?;
        let repo = self
            .preflight(pool, actor, &input.owner, &input.name, RepoAction::ContentsRead, deadline)
            .await?;
        let root = RootRef::new(repo.repository_id, input.root_id, 1).map_err(map_root_error)?;
        let mut client = super::acquire(pool, deadline).await?;
        let tx = super::begin_owned(&mut client, deadline).await?;
        if let Err(error) = crate::ref_store::pg::bound(&tx, deadline).await.map_err(super::map_refstore) {
            let _cleanup = rollback_strict(tx, deadline).await;
            drop(client);
            return Err(error);
        }
        let outcome = timeout_at(deadline, async {
            let record = PgRetentionRoots::root_record_in_tx(&tx, root).await;
            let record = match record {
                Ok(value) => value,
                Err(error) => {
                    return match final_authority_root(
                        &tx,
                        actor,
                        &repo,
                        RepoAction::ContentsRead,
                        &root_scope_from_gate(&repo, RootPurpose::Ci, PLACEHOLDER_BUSINESS_INTENT)?,
                        self.backend(),
                        None,
                        deadline,
                    )
                    .await
                    {
                        Ok(_) => Err(map_root_error(error)),
                        Err(auth_error) => Err(auth_error),
                    };
                }
            };
            let expected_scope = match &record {
                Some(record) => root_scope_from_record(record)?,
                None => root_scope_from_gate(&repo, RootPurpose::Ci, PLACEHOLDER_BUSINESS_INTENT)?,
            };
            final_authority_root(
                &tx,
                actor,
                &repo,
                RepoAction::ContentsRead,
                &expected_scope,
                self.backend(),
                None,
                deadline,
            )
            .await?;
            Ok::<Option<RootRecord>, Error>(record)
        })
        .await;
        let outcome = match outcome {
            Ok(result) => result,
            Err(_) => Err(super::deadline_error()),
        };
        let cleanup = rollback_strict(tx, deadline).await;
        drop(client);
        match (outcome, cleanup) {
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
            (Ok(record), Ok(())) => Ok(record),
        }
    }

    /// Authorized materialization. Current Admin+ContentsRead is checked before
    /// any Blob/native work; the core read uses only retained root rows; a fresh
    /// final transaction rechecks current auth/root/binding/backend/realm/cluster
    /// and successfully rolls back before the view is released.
    pub async fn materialize(
        &self,
        pool: &Pool,
        actor: &Identity,
        input: ServingRootRead,
        deadline: Instant,
    ) -> Result<RootReadView, Error> {
        Ok(self.materialize_with_context(pool, actor, input, deadline).await?.into_view())
    }

    pub(crate) async fn materialize_with_context(
        &self,
        pool: &Pool,
        actor: &Identity,
        input: ServingRootRead,
        deadline: Instant,
    ) -> Result<ServingRetainedRootReadContext, Error> {
        validate_owner_name(&input.owner, &input.name)?;
        validate_root_id(input.root_id)?;
        let deadline = root_deadline(deadline)?;
        let repo = self
            .preflight(pool, actor, &input.owner, &input.name, RepoAction::ContentsRead, deadline)
            .await?;
        let root = RootRef::new(repo.repository_id, input.root_id, 1).map_err(map_root_error)?;
        let view = match self.roots.materialize_serving(pool, root, deadline).await {
            Ok(view) => view,
            Err(error) => {
                return match self.authorize_current(pool, actor, &repo, deadline).await {
                    Ok(()) => Err(map_root_error(error)),
                    Err(auth_error) => Err(auth_error),
                };
            }
        };
        let cluster = view
            .serving_cluster_incarnation()
            .ok_or_else(|| Error::internal("serving root view has no cluster anchor"))?;
        self.finish_view(pool, actor, &repo, root, &view, cluster, deadline).await?;
        Ok(ServingRetainedRootReadContext {
            view,
            root,
            repository_id: repo.repository_id,
            tenant_id: repo.tenant_id,
            name: repo.name.clone(),
            cluster_incarnation: cluster,
            deadline,
        })
    }

    /// Future post-encoding fence. The caller must have fully read bytes and
    /// encoded its bounded JSON first; this rechecks the same root/binding/current
    /// realm/backend/cluster and late ContentsRead, then returns the view only
    /// after a successful bounded rollback. It uses the context's original
    /// deadline and never holds PostgreSQL across Blob/native/file/JSON work.
    pub(crate) async fn finalize_materialized(
        &self,
        pool: &Pool,
        actor: &Identity,
        context: ServingRetainedRootReadContext,
    ) -> Result<RootReadView, Error> {
        let deadline = context.deadline;
        let repo = AuthorizedRootRepo {
            repository_id: context.repository_id,
            tenant_id: context.tenant_id,
            owner: String::new(),
            name: context.name.clone(),
            gate: None,
        };
        let scope = *context.view.scope();
        let view = context.view;
        let root = context.root;
        let expected_binding = RequestDigest::from_str(&view.binding_digest_hex())
            .map_err(|_| Error::internal("retained root binding digest is invalid"))?;
        let expected_cluster = context.cluster_incarnation;
        self.finish_view_state(
            pool,
            actor,
            &repo,
            root,
            &view,
            &scope,
            expected_binding,
            expected_cluster,
            deadline,
        )
        .await?;
        Ok(view)
    }

    async fn release_existing(
        &self,
        pool: &Pool,
        actor: &Identity,
        repo: &AuthorizedRootRepo,
        root_id: Uuid,
        input: &ServingRootRelease,
        deadline: Instant,
    ) -> Result<RootReceipt, Error> {
        let root = RootRef::new(repo.repository_id, root_id, 1).map_err(map_root_error)?;
        let mut client = super::acquire(pool, deadline).await?;
        let tx = super::begin_owned(&mut client, deadline).await?;
        if let Err(error) = crate::ref_store::pg::bound(&tx, deadline).await.map_err(super::map_refstore) {
            let _cleanup = rollback_strict(tx, deadline).await;
            drop(client);
            return Err(error);
        }
        let outcome = timeout_at(deadline, async {
            let record = match PgRetentionRoots::root_record_in_tx(&tx, root).await {
                Ok(Some(record)) => record,
                Ok(None) => {
                    let scope = root_scope_from_gate(repo, RootPurpose::Ci, PLACEHOLDER_BUSINESS_INTENT)?;
                    match final_authority_root(
                        &tx,
                        actor,
                        repo,
                        RepoAction::ContentsWrite,
                        &scope,
                        self.backend(),
                        None,
                        deadline,
                    )
                    .await
                    {
                        Ok(_) => return Err(Error::not_found()),
                        Err(auth_error) => return Err(auth_error),
                    }
                }
                Err(error) => {
                    let scope = root_scope_from_gate(repo, RootPurpose::Ci, PLACEHOLDER_BUSINESS_INTENT)?;
                    return match final_authority_root(
                        &tx,
                        actor,
                        repo,
                        RepoAction::ContentsWrite,
                        &scope,
                        self.backend(),
                        None,
                        deadline,
                    )
                    .await
                    {
                        Ok(_) => Err(map_root_error(error)),
                        Err(auth_error) => Err(auth_error),
                    };
                }
            };
            let scope = root_scope_from_record(&record)?;
            let release_digest = derive_release_digest(
                repo.repository_id,
                root_id,
                &input.idempotency_key,
                &input.reason,
            );
            let release_request_id =
                derive_release_request_id(repo.repository_id, root_id, &input.idempotency_key);
            let request = ReleaseRootRequest::new(
                scope,
                root_id,
                1,
                release_request_id,
                record.register_digest_hex(),
                &release_digest.as_hex(),
                input.reason.clone(),
            )
            .map_err(map_root_error)?;
            let receipt = match self.roots.release_in_tx(&tx, &request, request.intent_digest()).await {
                Ok(receipt) => receipt,
                Err(error) => {
                    return match final_authority_root(
                        &tx,
                        actor,
                        repo,
                        RepoAction::ContentsWrite,
                        &scope,
                        self.backend(),
                        None,
                        deadline,
                    )
                    .await
                    {
                        Ok(_) => Err(map_root_error(error)),
                        Err(auth_error) => Err(auth_error),
                    };
                }
            };
            final_authority_root(
                &tx,
                actor,
                repo,
                RepoAction::ContentsWrite,
                &scope,
                self.backend(),
                None,
                deadline,
            )
            .await?;
            Ok::<RootReceipt, Error>(receipt)
        })
        .await;
        let outcome = match outcome {
            Ok(result) => result,
            Err(_) => Err(super::deadline_error()),
        };
        match outcome {
            Ok(receipt) => {
                super::commit_owned(tx, deadline).await?;
                Ok(receipt)
            }
            Err(error) => {
                let cleanup = rollback_strict(tx, deadline).await;
                drop(client);
                cleanup?;
                Err(error)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn release_absent(
        &self,
        pool: &Pool,
        actor: &Identity,
        repo: &AuthorizedRootRepo,
        root_id: Uuid,
        create: &ServingRootIntent,
        derived: &DerivedIntent,
        scope: &RootsScope,
        input: &ServingRootRelease,
        deadline: Instant,
    ) -> Result<RootReceipt, Error> {
        let release_digest =
            derive_release_digest(repo.repository_id, root_id, &input.idempotency_key, &input.reason);
        let release_request_id = derive_release_request_id(repo.repository_id, root_id, &input.idempotency_key);

        // Exact absent-root release replay is source-metadata independent.
        if let Some(receipt) = self
            .replay_release(
                pool,
                actor,
                repo,
                scope,
                root_id,
                release_request_id,
                release_digest,
                &input.reason,
                deadline,
            )
            .await?
        {
            return Ok(receipt);
        }

        // Load the original authorized A5 metadata data-only. This proves the
        // stored snapshot/ref/pack rows and current serving realm/backend, but it
        // does not require the source pin to be live.
        let source = self.stored_source_snapshot(pool, actor, repo, scope, create, deadline).await?;
        let reference = PackSnapshotRef::new(
            repo.repository_id,
            repo.tenant_id,
            source.snapshot_id(),
            source.pin_id(),
            source.pin_generation(),
        )
        .map_err(map_root_error)?;
        let operation_digest = prepare_request_digest(
            *scope,
            reference,
            derived.root_id,
            derived.operation_id,
            &create.selector,
            derived.register_request_id,
        )?;
        let expected_register_digest = crate::ref_store::core::retention_root::expected_register_digest_from_snapshot(
            *scope,
            reference,
            derived.root_id,
            derived.operation_id,
            operation_digest,
            &create.selector,
            &source,
        )
        .map_err(map_root_error)?;
        let request = ReleaseRootRequest::new(
            *scope,
            root_id,
            1,
            release_request_id,
            &expected_register_digest.as_hex(),
            &release_digest.as_hex(),
            input.reason.clone(),
        )
        .map_err(map_root_error)?;

        let mut client = super::acquire(pool, deadline).await?;
        let tx = super::begin_owned(&mut client, deadline).await?;
        if let Err(error) = crate::ref_store::pg::bound(&tx, deadline).await.map_err(super::map_refstore) {
            let _cleanup = rollback_strict(tx, deadline).await;
            drop(client);
            return Err(error);
        }
        let outcome = timeout_at(deadline, async {
            let receipt = match self.roots.release_in_tx(&tx, &request, request.intent_digest()).await {
                Ok(receipt) => receipt,
                Err(error) => {
                    return match final_authority_root(
                        &tx,
                        actor,
                        repo,
                        RepoAction::ContentsWrite,
                        scope,
                        self.backend(),
                        None,
                        deadline,
                    )
                    .await
                    {
                        Ok(_) => Err(map_root_error(error)),
                        Err(auth_error) => Err(auth_error),
                    };
                }
            };
            final_authority_root(
                &tx,
                actor,
                repo,
                RepoAction::ContentsWrite,
                scope,
                self.backend(),
                None,
                deadline,
            )
            .await?;
            Ok::<RootReceipt, Error>(receipt)
        })
        .await;
        let outcome = match outcome {
            Ok(result) => result,
            Err(_) => Err(super::deadline_error()),
        };
        match outcome {
            Ok(receipt) => {
                super::commit_owned(tx, deadline).await?;
                Ok(receipt)
            }
            Err(error) => {
                let cleanup = rollback_strict(tx, deadline).await;
                drop(client);
                cleanup?;
                Err(error)
            }
        }
    }

    async fn replay_create(
        &self,
        pool: &Pool,
        actor: &Identity,
        repo: &AuthorizedRootRepo,
        scope: &RootsScope,
        input: &ServingRootIntent,
        derived: &DerivedIntent,
        deadline: Instant,
    ) -> Result<Option<RootReceipt>, Error> {
        let root = RootRef::new(repo.repository_id, derived.root_id, 1).map_err(map_root_error)?;
        let mut client = super::acquire(pool, deadline).await?;
        let tx = super::begin_owned(&mut client, deadline).await?;
        if let Err(error) = crate::ref_store::pg::bound(&tx, deadline).await.map_err(super::map_refstore) {
            let _cleanup = rollback_strict(tx, deadline).await;
            drop(client);
            return Err(error);
        }
        let outcome = timeout_at(deadline, async {
            let replay = PgRetentionRoots::register_replay_in_tx(
                &tx,
                scope,
                root,
                derived.register_request_id,
            )
            .await;
            let replay = match replay {
                Ok(value) => value,
                Err(error) => {
                    return match final_authority_root(
                        &tx,
                        actor,
                        repo,
                        RepoAction::ContentsWrite,
                        scope,
                        self.backend(),
                        None,
                        deadline,
                    )
                    .await
                    {
                        Ok(_) => Err(map_root_error(error)),
                        Err(auth_error) => Err(auth_error),
                    };
                }
            };
            let Some((record, receipt)) = replay else {
                return Ok::<Option<RootReceipt>, Error>(None);
            };
            let exact = record_matches_intent(&record, repo, input, derived);
            final_authority_root(
                &tx,
                actor,
                repo,
                RepoAction::ContentsWrite,
                scope,
                self.backend(),
                None,
                deadline,
            )
            .await?;
            if !exact {
                return Err(Error(
                    StatusCode::CONFLICT,
                    "root create idempotency key was reused with a different intent",
                ));
            }
            Ok(Some(receipt))
        })
        .await;
        let outcome = match outcome {
            Ok(result) => result,
            Err(_) => Err(super::deadline_error()),
        };
        let cleanup = rollback_strict(tx, deadline).await;
        drop(client);
        match (outcome, cleanup) {
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
            (Ok(receipt), Ok(())) => Ok(receipt),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn replay_release(
        &self,
        pool: &Pool,
        actor: &Identity,
        repo: &AuthorizedRootRepo,
        scope: &RootsScope,
        root_id: Uuid,
        release_request_id: Uuid,
        release_digest: RequestDigest,
        reason: &str,
        deadline: Instant,
    ) -> Result<Option<RootReceipt>, Error> {
        let mut client = super::acquire(pool, deadline).await?;
        let tx = super::begin_owned(&mut client, deadline).await?;
        if let Err(error) = crate::ref_store::pg::bound(&tx, deadline).await.map_err(super::map_refstore) {
            let _cleanup = rollback_strict(tx, deadline).await;
            drop(client);
            return Err(error);
        }
        let outcome = timeout_at(deadline, async {
            let replay = PgRetentionRoots::release_replay_in_tx(
                &tx,
                scope,
                release_request_id,
                root_id,
                release_digest,
                reason,
            )
            .await;
            let replay = match replay {
                Ok(value) => value,
                Err(error) => {
                    return match final_authority_root(
                        &tx,
                        actor,
                        repo,
                        RepoAction::ContentsWrite,
                        scope,
                        self.backend(),
                        None,
                        deadline,
                    )
                    .await
                    {
                        Ok(_) => Err(map_root_error(error)),
                        Err(auth_error) => Err(auth_error),
                    };
                }
            };
            if replay.is_none() {
                return Ok::<Option<RootReceipt>, Error>(None);
            }
            final_authority_root(
                &tx,
                actor,
                repo,
                RepoAction::ContentsWrite,
                scope,
                self.backend(),
                None,
                deadline,
            )
            .await?;
            Ok(replay)
        })
        .await;
        let outcome = match outcome {
            Ok(result) => result,
            Err(_) => Err(super::deadline_error()),
        };
        let cleanup = rollback_strict(tx, deadline).await;
        drop(client);
        match (outcome, cleanup) {
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
            (Ok(receipt), Ok(())) => Ok(receipt),
        }
    }

    async fn source_snapshot(
        &self,
        pool: &Pool,
        actor: &Identity,
        repo: &AuthorizedRootRepo,
        scope: &RootsScope,
        intent: &ServingRootIntent,
        deadline: Instant,
    ) -> Result<PackReadSnapshot, Error> {
        let mut client = super::acquire(pool, deadline).await?;
        let tx = super::begin_owned(&mut client, deadline).await?;
        if let Err(error) = crate::ref_store::pg::bound(&tx, deadline).await.map_err(super::map_refstore) {
            let _cleanup = rollback_strict(tx, deadline).await;
            drop(client);
            return Err(error);
        }
        let outcome = timeout_at(deadline, async {
            match PgPackSnapshot
                .read_serving_by_snapshot(
                    &tx,
                    repo.repository_id,
                    repo.tenant_id,
                    intent.source_snapshot_id,
                    self.backend().as_hex(),
                    deadline,
                )
                .await
            {
                Ok(source) => Ok::<PackReadSnapshot, Error>(source),
                Err(error) => match final_authority_root(
                    &tx,
                    actor,
                    repo,
                    RepoAction::ContentsWrite,
                    scope,
                    self.backend(),
                    None,
                    deadline,
                )
                .await
                {
                    Ok(_) => Err(map_root_error(RootError::from(error))),
                    Err(auth_error) => Err(auth_error),
                },
            }
        })
        .await;
        let outcome = match outcome {
            Ok(result) => result,
            Err(_) => Err(super::deadline_error()),
        };
        let cleanup = rollback_strict(tx, deadline).await;
        drop(client);
        match (outcome, cleanup) {
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
            (Ok(source), Ok(())) => Ok(source),
        }
    }

    async fn stored_source_snapshot(
        &self,
        pool: &Pool,
        actor: &Identity,
        repo: &AuthorizedRootRepo,
        scope: &RootsScope,
        intent: &ServingRootIntent,
        deadline: Instant,
    ) -> Result<PackReadSnapshot, Error> {
        let mut client = super::acquire(pool, deadline).await?;
        let tx = super::begin_owned(&mut client, deadline).await?;
        if let Err(error) = crate::ref_store::pg::bound(&tx, deadline).await.map_err(super::map_refstore) {
            let _cleanup = rollback_strict(tx, deadline).await;
            drop(client);
            return Err(error);
        }
        let outcome = timeout_at(deadline, async {
            match PgPackSnapshot
                .read_stored_serving_by_snapshot(
                    &tx,
                    repo.repository_id,
                    repo.tenant_id,
                    intent.source_snapshot_id,
                    self.backend().as_hex(),
                    deadline,
                )
                .await
            {
                Ok(source) => Ok::<PackReadSnapshot, Error>(source),
                Err(error) => match final_authority_root(
                    &tx,
                    actor,
                    repo,
                    RepoAction::ContentsWrite,
                    scope,
                    self.backend(),
                    None,
                    deadline,
                )
                .await
                {
                    Ok(_) => Err(map_root_error(RootError::from(error))),
                    Err(auth_error) => Err(auth_error),
                },
            }
        })
        .await;
        let outcome = match outcome {
            Ok(result) => result,
            Err(_) => Err(super::deadline_error()),
        };
        let cleanup = rollback_strict(tx, deadline).await;
        drop(client);
        match (outcome, cleanup) {
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
            (Ok(source), Ok(())) => Ok(source),
        }
    }

    async fn finish_view(
        &self,
        pool: &Pool,
        actor: &Identity,
        repo: &AuthorizedRootRepo,
        root: RootRef,
        view: &RootReadView,
        cluster: Uuid,
        deadline: Instant,
    ) -> Result<(), Error> {
        let scope = *view.scope();
        let binding = RequestDigest::from_str(&view.binding_digest_hex())
            .map_err(|_| Error::internal("retained root binding digest is invalid"))?;
        self.finish_view_state(pool, actor, repo, root, view, &scope, binding, cluster, deadline)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn finish_view_state(
        &self,
        pool: &Pool,
        actor: &Identity,
        repo: &AuthorizedRootRepo,
        root: RootRef,
        view: &RootReadView,
        scope: &RootsScope,
        expected_binding: RequestDigest,
        expected_cluster: Uuid,
        deadline: Instant,
    ) -> Result<(), Error> {
        let _ = view;
        let mut client = super::acquire(pool, deadline).await?;
        let tx = super::begin_owned(&mut client, deadline).await?;
        if let Err(error) = crate::ref_store::pg::bound(&tx, deadline).await.map_err(super::map_refstore) {
            let _cleanup = rollback_strict(tx, deadline).await;
            drop(client);
            return Err(error);
        }
        let outcome = timeout_at(deadline, async {
            let state = PgRetentionRoots::validate_serving_root_state_in_tx(
                &tx,
                root,
                expected_binding,
                expected_cluster,
                self.backend().as_hex(),
            )
            .await;
            if let Err(error) = state {
                return match final_authority_root(
                    &tx,
                    actor,
                    repo,
                    RepoAction::ContentsRead,
                    scope,
                    self.backend(),
                    None,
                    deadline,
                )
                .await
                {
                    Ok(_) => Err(map_root_error(error)),
                    Err(auth_error) => Err(auth_error),
                };
            }
            final_authority_root(
                &tx,
                actor,
                repo,
                RepoAction::ContentsRead,
                scope,
                self.backend(),
                Some(expected_cluster),
                deadline,
            )
            .await?;
            Ok::<(), Error>(())
        })
        .await;
        let outcome = match outcome {
            Ok(result) => result,
            Err(_) => Err(super::deadline_error()),
        };
        let cleanup = rollback_strict(tx, deadline).await;
        drop(client);
        match (outcome, cleanup) {
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
            (Ok(()), Ok(())) => Ok(()),
        }
    }

    async fn authorize_current(
        &self,
        pool: &Pool,
        actor: &Identity,
        repo: &AuthorizedRootRepo,
        deadline: Instant,
    ) -> Result<(), Error> {
        let mut client = super::acquire(pool, deadline).await?;
        let tx = super::begin_owned(&mut client, deadline).await?;
        if let Err(error) = crate::ref_store::pg::bound(&tx, deadline).await.map_err(super::map_refstore) {
            let _cleanup = rollback_strict(tx, deadline).await;
            drop(client);
            return Err(error);
        }
        let scope = root_scope_from_gate(repo, RootPurpose::Ci, PLACEHOLDER_BUSINESS_INTENT)?;
        let outcome = timeout_at(deadline, async {
            final_authority_root(
                &tx,
                actor,
                repo,
                RepoAction::ContentsRead,
                &scope,
                self.backend(),
                None,
                deadline,
            )
            .await
            .map(|_| ())
        })
        .await;
        let outcome = match outcome {
            Ok(result) => result,
            Err(_) => Err(super::deadline_error()),
        };
        let cleanup = rollback_strict(tx, deadline).await;
        drop(client);
        match (outcome, cleanup) {
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
            (Ok(()), Ok(())) => Ok(()),
        }
    }

    async fn preflight(
        &self,
        pool: &Pool,
        actor: &Identity,
        owner: &str,
        name: &str,
        action: RepoAction,
        deadline: Instant,
    ) -> Result<AuthorizedRootRepo, Error> {
        validate_owner_name(owner, name)?;
        let mut client = super::acquire(pool, deadline).await?;
        let tx = super::begin_owned(&mut client, deadline).await?;
        if let Err(error) = crate::ref_store::pg::bound(&tx, deadline).await.map_err(super::map_refstore) {
            let _cleanup = rollback_strict(tx, deadline).await;
            drop(client);
            return Err(error);
        }
        let outcome = timeout_at(deadline, async {
            let access = auth::authorize_repo_with_role(
                &tx,
                actor,
                owner,
                name,
                Role::Admin,
                action,
            )
            .await?;
            let locked = LockedScope::lock(&tx, access.repo_id, false)
                .await
                .map_err(super::map_refstore)?
                .ok_or_else(Error::not_found)?;
            if locked.owner_id() != access.owner_id || locked.name() != name {
                return Err(Error::not_found());
            }
            locked
                .require_serving(access.owner_id, self.backend().as_hex())
                .map_err(super::map_scope_refusal)?;
            let gate = PgRefStoreCore
                .read_gate_in_tx(&tx, access.repo_id, false)
                .await
                .map_err(super::map_refstore)?
                .ok_or_else(Error::not_found)?;
            locked
                .require_binding_matches_gate(&gate)
                .map_err(super::map_scope_refusal)?;
            if gate.repository_id() != access.repo_id
                || gate.tenant_id() != access.owner_id
                || gate.object_format() != locked.object_format()
            {
                return Err(Error::internal("durable serving gate/binding realm mismatch"));
            }
            Ok(AuthorizedRootRepo {
                repository_id: access.repo_id,
                tenant_id: access.owner_id,
                owner: owner.to_owned(),
                name: name.to_owned(),
                gate: Some(gate),
            })
        })
        .await;
        let outcome = match outcome {
            Ok(result) => result,
            Err(_) => Err(super::deadline_error()),
        };
        let cleanup = rollback_strict(tx, deadline).await;
        drop(client);
        match (outcome, cleanup) {
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
            (Ok(repo), Ok(())) => Ok(repo),
        }
    }
}

struct AuthorizedRootRepo {
    repository_id: Uuid,
    tenant_id: Uuid,
    owner: String,
    name: String,
    /// `None` is used only by the already-authorized context finalizer, which
    /// re-reads the live realm through `final_authority_with_cluster`.
    gate: Option<CoreGate>,
}

impl AuthorizedRootRepo {
    fn gate(&self) -> Result<&CoreGate, Error> {
        self.gate.as_ref().ok_or_else(|| Error::internal("root preflight gate is unavailable"))
    }
}

struct DerivedIntent {
    root_id: Uuid,
    operation_id: Uuid,
    register_request_id: Uuid,
    business_intent: RequestDigest,
    canonical_oids: Vec<String>,
}

fn validate_owner_name(owner: &str, name: &str) -> Result<(), Error> {
    if !db::valid_name(owner) || !db::valid_name(name) {
        return Err(Error::not_found());
    }
    Ok(())
}

fn validate_key(key: &str) -> Result<(), Error> {
    if key.is_empty()
        || key.len() > ROOT_IDEMPOTENCY_MAX
        || key.chars().any(char::is_control)
    {
        return Err(Error(StatusCode::BAD_REQUEST, "invalid root idempotency key"));
    }
    Ok(())
}

fn validate_reason(reason: &str) -> Result<(), Error> {
    if reason.is_empty() || reason.len() > ROOT_REASON_MAX || reason.chars().any(char::is_control) {
        return Err(Error(StatusCode::BAD_REQUEST, "invalid root release reason"));
    }
    Ok(())
}

fn validate_root_id(root_id: Uuid) -> Result<(), Error> {
    if root_id.is_nil() {
        return Err(Error(StatusCode::BAD_REQUEST, "invalid root id"));
    }
    Ok(())
}

fn validate_intent(intent: &ServingRootIntent) -> Result<(), Error> {
    if intent.source_snapshot_id.is_nil() {
        return Err(Error(StatusCode::BAD_REQUEST, "invalid source snapshot id"));
    }
    validate_key(&intent.idempotency_key)
}

fn root_deadline(deadline: Instant) -> Result<Instant, Error> {
    crate::ref_store::core::retention_root::effective_deadline(deadline)
        .map_err(map_root_error)
}

fn derive_intent(gate: &CoreGate, intent: &ServingRootIntent) -> Result<DerivedIntent, Error> {
    validate_intent(intent)?;
    let kind = intent.selector.kind();
    let canonical_oids = canonical_selector(&intent.selector, gate.object_format())?;
    let mut fields: Vec<Vec<u8>> = vec![
        gate.repository_id().as_bytes().to_vec(),
        intent.source_snapshot_id.as_bytes().to_vec(),
        intent.purpose.as_str().as_bytes().to_vec(),
        kind.as_str().as_bytes().to_vec(),
    ];
    for oid in &canonical_oids {
        fields.push(oid.as_bytes().to_vec());
    }
    let parts = fields.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let business_intent = RequestDigest::of(ROOT_BUSINESS_INTENT_DOMAIN, &parts);
    let root_id = derived_uuid(ROOT_ID_DOMAIN, gate.repository_id(), &intent.idempotency_key);
    let operation_id = derived_uuid(ROOT_OPERATION_DOMAIN, gate.repository_id(), &intent.idempotency_key);
    let register_request_id =
        derived_uuid(ROOT_REGISTER_REQUEST_DOMAIN, gate.repository_id(), &intent.idempotency_key);
    Ok(DerivedIntent {
        root_id,
        operation_id,
        register_request_id,
        business_intent,
        canonical_oids,
    })
}

fn canonical_selector(selector: &RootSelector, format: crate::ref_store::GitObjectFormat) -> Result<Vec<String>, Error> {
    crate::ref_store::core::retention_root::canonical_intent_oids(selector, format)
        .map_err(map_root_error)
}

fn root_scope(
    repo: &AuthorizedRootRepo,
    purpose: RootPurpose,
    business_intent: &RequestDigest,
) -> Result<RootsScope, Error> {
    let gate = repo.gate()?;
    RootsScope::new(
        repo.repository_id,
        repo.tenant_id,
        repo.tenant_id,
        purpose,
        &business_intent.as_hex(),
        gate.object_format(),
        gate.history_incarnation(),
        gate.authority_epoch(),
        gate.group_epoch(),
    )
    .map_err(map_root_error)
}

fn root_scope_from_gate(
    repo: &AuthorizedRootRepo,
    purpose: RootPurpose,
    business_intent_hex: &str,
) -> Result<RootsScope, Error> {
    let gate = repo.gate()?;
    RootsScope::new(
        repo.repository_id,
        repo.tenant_id,
        repo.tenant_id,
        purpose,
        business_intent_hex,
        gate.object_format(),
        gate.history_incarnation(),
        gate.authority_epoch(),
        gate.group_epoch(),
    )
    .map_err(map_root_error)
}

fn root_scope_from_record(record: &RootRecord) -> Result<RootsScope, Error> {
    RootsScope::new(
        record.repository_id(),
        record.tenant_id(),
        record.owner_id(),
        record.purpose(),
        record.business_intent_digest_hex(),
        record.object_format(),
        record.history_incarnation(),
        record.authority_epoch(),
        record.group_epoch(),
    )
    .map_err(map_root_error)
}

fn root_metadata_scope(scope: &RootsScope) -> Result<MetadataSnapshotScope, Error> {
    MetadataSnapshotScope::new(
        scope.repository_id(),
        scope.tenant_id(),
        scope.tenant_id(),
        MetadataPinPurpose::Verification,
        scope.object_format(),
        scope.history_incarnation(),
        scope.authority_epoch(),
        scope.group_epoch(),
    )
    .map_err(super::map_refstore)
}

fn record_matches_intent(
    record: &RootRecord,
    repo: &AuthorizedRootRepo,
    intent: &ServingRootIntent,
    derived: &DerivedIntent,
) -> bool {
    let Ok(gate) = repo.gate() else { return false };
    record.repository_id() == repo.repository_id
        && record.tenant_id() == repo.tenant_id
        && record.owner_id() == repo.tenant_id
        && record.root_id() == derived.root_id
        && record.source_snapshot_id() == intent.source_snapshot_id
        && record.purpose() == intent.purpose
        && record.operation_id() == derived.operation_id
        && record.request_id() == derived.register_request_id
        && record.business_intent_digest_hex() == derived.business_intent.as_hex().as_str()
        && record.selector_kind() == intent.selector.kind()
        && record.object_format() == gate.object_format()
        && record.history_incarnation() == gate.history_incarnation()
        && record.authority_epoch() == gate.authority_epoch()
        && record.group_epoch() == gate.group_epoch()
        && record_digest_matches(record, derived, intent)
        && match &intent.selector {
            RootSelector::Snapshot => true,
            RootSelector::ObjectIds(_) => record.root_oids() == derived.canonical_oids.as_slice(),
        }
}

fn prepare_request_digest(
    scope: RootsScope,
    reference: PackSnapshotRef,
    root_id: Uuid,
    operation_id: Uuid,
    selector: &RootSelector,
    register_request_id: Uuid,
) -> Result<RequestDigest, Error> {
    PrepareRootRequest::new(
        scope,
        reference,
        root_id,
        operation_id,
        selector.clone(),
        register_request_id,
    )
    .map(|request| request.digest())
    .map_err(map_root_error)
}

fn record_digest_matches(
    record: &RootRecord,
    derived: &DerivedIntent,
    intent: &ServingRootIntent,
) -> bool {
    let Ok(scope) = root_scope_from_record(record) else { return false };
    let Ok(reference) = PackSnapshotRef::new(
        record.repository_id(),
        record.tenant_id(),
        record.source_snapshot_id(),
        record.source_pin_id(),
        record.source_pin_generation(),
    ) else {
        return false;
    };
    let Ok(digest) = prepare_request_digest(
        scope,
        reference,
        derived.root_id,
        derived.operation_id,
        &intent.selector,
        derived.register_request_id,
    ) else {
        return false;
    };
    record.operation_digest_hex() == digest.as_hex().as_str()
}

fn register_request_digest(candidate: &RootCandidate, request_id: Uuid) -> RequestDigest {
    RequestDigest::of(
        REGISTER_REQUEST_DIGEST_DOMAIN,
        &[
            candidate.register_digest().as_bytes(),
            request_id.as_bytes(),
            b"register",
        ],
    )
}

fn derive_release_request_id(repository_id: Uuid, root_id: Uuid, key: &str) -> Uuid {
    derived_uuid_with_root(ROOT_RELEASE_REQUEST_DOMAIN, repository_id, root_id, key)
}

fn derive_release_digest(
    repository_id: Uuid,
    root_id: Uuid,
    key: &str,
    reason: &str,
) -> RequestDigest {
    RequestDigest::of(
        ROOT_RELEASE_INTENT_DOMAIN,
        &[
            repository_id.as_bytes(),
            root_id.as_bytes(),
            key.as_bytes(),
            reason.as_bytes(),
        ],
    )
}

fn derived_uuid(domain: &str, repository_id: Uuid, key: &str) -> Uuid {
    let digest = RequestDigest::of(domain, &[repository_id.as_bytes(), key.as_bytes()]);
    uuid_from_digest(digest)
}

fn derived_uuid_with_root(domain: &str, repository_id: Uuid, root_id: Uuid, key: &str) -> Uuid {
    let digest = RequestDigest::of(
        domain,
        &[repository_id.as_bytes(), root_id.as_bytes(), key.as_bytes()],
    );
    uuid_from_digest(digest)
}

fn uuid_from_digest(digest: RequestDigest) -> Uuid {
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn map_root_error(error: RootError) -> Error {
    match error {
        RootError::Store(error) => match error {
            RefStoreError::MetadataPinExpired { .. } | RefStoreError::MetadataPinReleased { .. } => {
                Error(StatusCode::CONFLICT, "source snapshot pin is no longer live")
            }
            RefStoreError::MetadataPinNotFound { .. }
            | RefStoreError::MetadataSnapshotNotFound { .. }
            | RefStoreError::RepositoryNotFound => Error::not_found(),
            RefStoreError::MetadataScopeMismatch(_) | RefStoreError::MetadataGateVersionMismatch => {
                Error(StatusCode::CONFLICT, "repository realm changed; retry the same request")
            }
            RefStoreError::MetadataQuotaExceeded { .. } => {
                Error(StatusCode::TOO_MANY_REQUESTS, "retained root quota is exhausted")
            }
            RefStoreError::MetadataSnapshotTooLarge { .. } => {
                Error(StatusCode::PAYLOAD_TOO_LARGE, "root selector/source is too large")
            }
            other => super::map_refstore(other),
        },
        RootError::RootNotFound { .. } => Error::not_found(),
        RootError::RootReleased { .. } | RootError::RootAlreadyActive { .. } => {
            Error(StatusCode::CONFLICT, "retention root state conflicts with this request")
        }
        RootError::RootGenerationConflict { .. } | RootError::RootDigestConflict(_) => {
            Error(StatusCode::CONFLICT, "retention root intent conflicts with durable state")
        }
        RootError::RootSourceChanged(_) => {
            Error(StatusCode::CONFLICT, "source snapshot changed; retry the same request")
        }
        RootError::RootSelectorInvalid(_) => Error(StatusCode::BAD_REQUEST, "invalid root selector"),
        RootError::RootObjectMissing { .. } => {
            Error(StatusCode::CONFLICT, "root selector is not present in the captured closure")
        }
        RootError::RootQuotaExceeded { .. } => {
            Error(StatusCode::TOO_MANY_REQUESTS, "retained root quota is exhausted")
        }
        RootError::RootReceiptTooLarge { .. } => {
            Error(StatusCode::PAYLOAD_TOO_LARGE, "retained root receipt is too large")
        }
        RootError::RootRealmMismatch(_) | RootError::RootAuthorityRequired(_) => {
            Error(StatusCode::CONFLICT, "repository authority changed; retry the same request")
        }
        RootError::RootClosureUnproven(_) => Error::internal("retained root closure could not be proven"),
    }
}

async fn final_authority_root(
    tx: &Transaction<'_>,
    actor: &Identity,
    repo: &AuthorizedRootRepo,
    action: RepoAction,
    scope: &RootsScope,
    backend: &BlobBackendIdentity,
    expected_cluster: Option<Uuid>,
    deadline: Instant,
) -> Result<Uuid, Error> {
    let expected_scope = root_metadata_scope(scope)?;
    let (_gate, cluster) = super::snapshot_metadata::final_authority_with_cluster(
        tx,
        actor,
        repo.repository_id,
        repo.tenant_id,
        &repo.name,
        action,
        backend,
        Some(&expected_scope),
        false,
        deadline,
    )
    .await?;
    if let Some(expected) = expected_cluster
        && cluster != expected
    {
        return Err(Error(
            StatusCode::CONFLICT,
            "cluster authority incarnation changed; retry the same request",
        ));
    }
    Ok(cluster)
}

async fn rollback_strict(tx: Transaction<'_>, deadline: Instant) -> Result<(), Error> {
    match timeout_at(deadline, tx.rollback()).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) | Err(_) => Err(Error(
            StatusCode::SERVICE_UNAVAILABLE,
            "retention root transaction cleanup failed",
        )),
    }
}

// Keep the imported owner field meaningful for future diagnostics without
// exposing it in any HTTP projection.
#[allow(dead_code)]
fn authorized_owner(repo: &AuthorizedRootRepo) -> &str {
    &repo.owner
}
