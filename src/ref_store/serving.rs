//! Gateway-facing `pg_refstore` serving API (#143/#107).
//!
//! This module is the only engine surface a gateway needs:
//!
//! * [`provision`] durably creates a **fresh** repository on the disjoint
//!   `pg_refstore` backend and initializes its authority in one short owned
//!   PostgreSQL transaction: migration-139 core gate (revision 1),
//!   migration-144 protocol realm, migration-145 serving binding (owner,
//!   repository name/id, object format, `history_incarnation`, authority/group
//!   epochs and the digest of the *actually opened* Blob backend) and only then
//!   `ready`. It is idempotent: a retry (including after an ambiguous `COMMIT`)
//!   reads the durable intent back and finishes the same gate/protocol/binding
//!   with the same stored random ids — it never mints a second authority and
//!   never re-rolls `history_incarnation`. Concurrent retries for the same
//!   owner/name converge on the single `UNIQUE (owner_id, name)` intent row.
//! * [`lookup`] resolves an already served repository after the caller's
//!   *current* credentials/RBAC/scope authorization, then verifies the strict
//!   shared predicate ([`serving_scope`](crate::ref_store::core::serving_scope)):
//!   the durable binding must be ready, its realm must equal the live core gate
//!   realm, and its stored Blob backend digest must equal the identity of the
//!   concrete store this process has open. A bare `repositories.state='ready'`
//!   row, a forged `storage_backend` string or a stored hex value is never
//!   authority.
//!
//! The durable binding names the exact row (id, owner, name, object format,
//! history, both epochs, opened Blob digest). Migration-145 triggers and the
//! shared locked predicate both enforce it; every pool checkout is deadline
//! bounded (`max_size = 1` is supported) and released before a post-commit read.
//!
//! Both entry points are internal trusted-caller APIs: the backend identity is
//! passed by the engine from the store it actually opened and is never accepted
//! from HTTP. [`crate::blob_store::BlobBackendIdentity`] has private
//! constructors outside the `blob_store` subtree, so an HTTP layer cannot mint
//! one.
//!
//! No Git/Blob/network IO runs inside a PostgreSQL transaction and no legacy
//! `gitfs`/Pando authority is adopted: a ready `gitfs`/Pando repository is
//! refused, and migration 145 refuses Pando/projection writes for a bound
//! repository, so there is no second write authority.
use crate::{
    Error, auth,
    db::{self, Identity, Repository},
    members::models::Role,
    organizations,
    ref_store::{
        CoreGate,
        contract::RefStoreError,
        core::{
            CoreGateInit, GitObjectFormat, PgDecisionProtocol, PgRefStoreCore, RealmExpectation, RefName,
            serving_scope::{CoreRealm, LockedScope, PG_REFSTORE_BACKEND, ScopeRefusal},
        },
        pg::bound,
    },
    token_scopes::RepoAction,
};
use axum::http::StatusCode;
use deadpool_postgres::{Pool, Transaction};
use std::time::Duration;
use tokio::time::{Instant, timeout_at};
use uuid::Uuid;

/// Default branch a freshly provisioned core gate starts on.
const DEFAULT_HEAD_REF: &str = "refs/heads/main";
/// Both epochs of a brand-new authority intent.
const INITIAL_EPOCH: i64 = 1;

/// Trusted-caller request to create or recover one `pg_refstore` repository.
#[derive(Clone, Debug)]
pub struct ProvisionRequest {
    /// Owner namespace slug; `None` means the acting user's own namespace.
    pub owner: Option<String>,
    pub name: String,
    pub object_format: GitObjectFormat,
}

/// Result of [`provision`]. `created` is `true` only when this call inserted the
/// durable repository row; a retry returns the same repository with `false`.
#[derive(Clone)]
pub struct ProvisionReceipt {
    pub repository: Repository,
    pub created: bool,
}

impl std::fmt::Debug for ProvisionReceipt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `db::Repository` has no Debug; print only the non-secret identity.
        formatter
            .debug_struct("ProvisionReceipt")
            .field("repository_id", &self.repository.id)
            .field("state", &self.repository.state)
            .field("created", &self.created)
            .finish()
    }
}

/// An authorized, verified serving repository and its live core gate proof.
#[derive(Clone)]
pub struct ServingRepository {
    pub repository: Repository,
    pub gate: CoreGate,
    /// The non-nil `public.cluster_authority.incarnation` this lookup read in
    /// its own bounded transaction after authorization. A later serving read
    /// capture must prove the identical value before it may materialize.
    pub cluster_incarnation: Uuid,
}

impl std::fmt::Debug for ServingRepository {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ServingRepository")
            .field("repository_id", &self.repository.id)
            .field("revision", &self.gate.revision())
            .field("cluster_incarnation", &self.cluster_incarnation)
            .finish()
    }
}

/// Check out one pooled connection without outliving the caller deadline.
///
/// A `max_size = 1` pool is a supported deployment: every checkout is bounded
/// by the same absolute deadline as the transaction, so a missing release is a
/// timeout instead of an unbounded wait.
async fn acquire(pool: &Pool, deadline: Instant) -> Result<deadpool_postgres::Client, Error> {
    match timeout_at(deadline, pool.get()).await {
        Ok(Ok(client)) => Ok(client),
        Ok(Err(error)) => Err(Error::internal(error)),
        Err(_) => Err(deadline_error()),
    }
}

/// Start one pooled transaction without outliving the caller's deadline.
async fn begin_owned<'a>(
    client: &'a mut deadpool_postgres::Client,
    deadline: Instant,
) -> Result<Transaction<'a>, Error> {
    match timeout_at(deadline, client.transaction()).await {
        Ok(Ok(tx)) => Ok(tx),
        Ok(Err(error)) => Err(Error::internal(error)),
        Err(_) => Err(deadline_error()),
    }
}

/// Commit or report an explicitly unknown outcome.
///
/// The deadline is checked before `COMMIT` is issued (an expired deadline
/// rolls back and reports a timeout). Once `COMMIT` is sent, only an
/// acknowledged success is `Ok`; a timeout or an error reply is a retryable
/// `503` because the durable intent may still have committed and the retry
/// resolves it idempotently. This never claims an abort it cannot prove.
async fn commit_owned(tx: Transaction<'_>, deadline: Instant) -> Result<(), Error> {
    if Instant::now() >= deadline {
        let _ = timeout_at(Instant::now() + Duration::from_secs(2), tx.rollback()).await;
        return Err(deadline_error());
    }
    match timeout_at(deadline, tx.commit()).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) | Err(_) => Err(commit_unknown_error()),
    }
}

fn deadline_error() -> Error {
    Error(StatusCode::GATEWAY_TIMEOUT, "ref-store deadline expired")
}

fn commit_unknown_error() -> Error {
    Error(
        StatusCode::SERVICE_UNAVAILABLE,
        "ref-store commit outcome is unknown; retry the same request to resolve it idempotently",
    )
}

fn map_refstore(error: RefStoreError) -> Error {
    match error {
        RefStoreError::Timeout => deadline_error(),
        RefStoreError::CommitUnknown { .. } | RefStoreError::MetadataCommitUnknown { .. } => commit_unknown_error(),
        RefStoreError::GateConflict
        | RefStoreError::DigestConflict
        | RefStoreError::IdentityConflict
        | RefStoreError::TerminalImmutable => {
            Error(StatusCode::CONFLICT, "provisioning intent conflicts with the durable authority")
        }
        RefStoreError::Unsupported(_) | RefStoreError::InvalidIdentity(_) => {
            Error(StatusCode::CONFLICT, "repository cannot be provisioned on the pg_refstore backend")
        }
        RefStoreError::RepositoryNotFound => Error::not_found(),
        other => Error::internal(other),
    }
}

/// Map a shared-predicate refusal to the gateway-facing status. Lookup refusals
/// stay non-disclosing (`not_found`) unless they are a durable binding conflict.
fn map_scope_refusal(refusal: ScopeRefusal) -> Error {
    match refusal {
        ScopeRefusal::Tenant | ScopeRefusal::MissingBinding | ScopeRefusal::NotServing => Error::not_found(),
        ScopeRefusal::BackendIdentity => Error(StatusCode::CONFLICT, "repository is bound to a different Blob backend"),
        ScopeRefusal::LegacyAuthority => Error::not_found(),
        _ => Error::internal(refusal.reason()),
    }
}

fn map_scope_conflict(refusal: ScopeRefusal) -> Error {
    match refusal {
        ScopeRefusal::Inconsistent(_) => Error::internal(refusal.reason()),
        _ => Error(StatusCode::CONFLICT, "provisioning intent conflicts with the durable repository authority"),
    }
}

/// Create (`created = true`) or idempotently recover (`created = false`) one
/// durable `pg_refstore` repository and its authority.
///
/// Authorization is the real repository-creation path: the current token is
/// verified, a restricted token is refused explicitly (no create scope exists
/// yet), and the owner namespace must belong to the actor (user namespace) or
/// grant the actor `maintain` (organization). The tenant identity of every
/// authority row is that owner namespace id, never the actor id.
///
/// The owned transaction is short and bounded: forced durable WAL
/// acknowledgement (`SET LOCAL synchronous_commit = 'on'`), statement/lock
/// timeouts from the caller deadline, no Git/Blob IO. Only an acknowledged
/// `COMMIT` returns `Ok`; an ambiguous `COMMIT` returns a retryable
/// `503`, and the retry resolves it through the same stored intent ids.
pub async fn provision(
    pool: &Pool,
    actor: &Identity,
    input: ProvisionRequest,
    backend: &crate::blob_store::BlobBackendIdentity,
    deadline: Instant,
) -> Result<ProvisionReceipt, Error> {
    auth::writable(actor)?;
    if !db::valid_name(&input.name) {
        return Err(Error::bad_request());
    }
    let owner_slug = match input.owner.clone() {
        Some(owner) => owner,
        None => actor.username.clone(),
    };
    if !db::valid_name(&owner_slug) {
        return Err(Error::not_found());
    }
    let mut client = acquire(pool, deadline).await?;
    let tx = begin_owned(&mut client, deadline).await?;
    let outcome = provision_in_tx(&tx, actor, &owner_slug, &input, backend, deadline).await;
    match outcome {
        Ok((repository_id, created)) => {
            commit_owned(tx, deadline).await?;
            drop(client);
            let repository = read_repository(pool, repository_id, deadline).await?;
            Ok(ProvisionReceipt { repository, created })
        }
        Err(error) => {
            let _ = tx.rollback().await;
            Err(error)
        }
    }
}

/// Provision inside the caller-owned transaction. Returns the durable
/// repository id and whether this call created the repository row.
async fn provision_in_tx(
    tx: &Transaction<'_>,
    actor: &Identity,
    owner_slug: &str,
    input: &ProvisionRequest,
    backend: &crate::blob_store::BlobBackendIdentity,
    deadline: Instant,
) -> Result<(Uuid, bool), Error> {
    // Force durable WAL acknowledgement for this transaction.
    tx.execute("SET LOCAL synchronous_commit = 'on'", &[]).await.map_err(Error::internal)?;
    bound(tx, deadline).await.map_err(map_refstore)?;

    // Current token first, then the explicit restricted-token create refusal,
    // then the real namespace-create authorization.
    auth::verify_token(tx, actor, true).await?;
    auth::reject_restricted_create(tx, actor).await?;
    let owner_id = organizations::authorize_namespace_create(tx, actor, owner_slug).await?;

    // 1. Durable repository row. A concurrent provisioning of the same
    //    owner/name loses this insert and then adopts the winner's row.
    let requested_id = Uuid::new_v4();
    let object_format = input.object_format.as_str().to_owned();
    let inserted = tx
        .query_opt(
            "INSERT INTO repositories(id,owner_id,name,state,storage_backend,object_format)
             VALUES($1,$2,$3,'provisioning','pg_refstore',$4)
             ON CONFLICT (owner_id,name) DO NOTHING
             RETURNING id",
            &[&requested_id, &owner_id, &input.name, &object_format],
        )
        .await
        .map_err(Error::internal)?;
    let created = inserted.is_some();
    let repository_id: Uuid = match inserted {
        Some(row) => row.get(0),
        None => tx
            .query_opt("SELECT id FROM repositories WHERE owner_id=$1 AND name=$2", &[&owner_id, &input.name])
            .await
            .map_err(Error::internal)?
            .ok_or_else(Error::not_found)?
            .get(0),
    };

    // 2. Lock and classify the durable repository row. Any pre-existing legacy
    //    GitFS/Pando authority (or a row on another backend) is refused: the
    //    service never adopts an existing authority and never creates a second.
    let scope = LockedScope::lock(tx, repository_id, true)
        .await
        .map_err(map_refstore)?
        .ok_or_else(|| Error::internal("repository row disappeared during provisioning"))?;
    if scope.owner_id() != owner_id {
        return Err(Error::not_found());
    }
    if scope.storage_backend() != PG_REFSTORE_BACKEND {
        return Err(Error(
            StatusCode::CONFLICT,
            "repository exists on another storage backend; the pg_refstore service cannot adopt it",
        ));
    }
    if scope.transition_state() != crate::ref_store::core::serving_scope::STABLE_TRANSITION {
        return Err(Error(StatusCode::CONFLICT, "repository storage transition is not stable"));
    }
    if scope.pando_authority() || scope.legacy_refs() {
        return Err(Error(StatusCode::CONFLICT, "repository has a legacy Pando authority or legacy ref projection"));
    }
    if scope.object_format() != input.object_format {
        return Err(Error(StatusCode::CONFLICT, "repository object format cannot change"));
    }

    // 3. Durable serving intent. `history_incarnation` is minted only when this
    //    insert actually creates the intent; a retry keeps the stored value.
    if scope.binding().is_none() {
        let fresh_history = Uuid::new_v4();
        tx.execute(
            "INSERT INTO ref_store_serving_repositories
                 (repository_id,owner_id,name,object_format,history_incarnation,authority_epoch,group_epoch,
                  backend_identity,state)
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,'pending')
             ON CONFLICT (owner_id,name) DO NOTHING",
            &[
                &repository_id,
                &owner_id,
                &input.name,
                &object_format,
                &fresh_history,
                &INITIAL_EPOCH,
                &INITIAL_EPOCH,
                &backend.as_hex(),
            ],
        )
        .await
        .map_err(Error::internal)?;
    }

    // Re-lock so the (possibly pre-existing) intent is read under `FOR UPDATE`.
    let scope = LockedScope::lock(tx, repository_id, true)
        .await
        .map_err(map_refstore)?
        .ok_or_else(|| Error::internal("repository row disappeared during provisioning"))?;
    let binding =
        scope.binding().ok_or_else(|| Error::internal("durable serving intent is missing after its insert"))?.clone();
    if binding.repository_id() != repository_id || binding.owner_id() != owner_id {
        return Err(Error::internal("serving intent names another repository"));
    }
    if binding.name() != scope.name() || binding.object_format() != scope.object_format() {
        return Err(Error::internal("serving intent names another repository name/object format"));
    }
    if binding.object_format() != input.object_format {
        return Err(Error(StatusCode::CONFLICT, "repository object format cannot change"));
    }
    if binding.backend_identity() != backend.as_hex() {
        return Err(Error(StatusCode::CONFLICT, "repository is bound to a different Blob backend"));
    }

    // 4. Bootstrap/replay gate + protocol realm from the *stored* intent values.
    let realm = CoreRealm::new(
        owner_id,
        binding.object_format(),
        binding.history_incarnation(),
        binding.authority_epoch(),
        binding.group_epoch(),
    );
    let lane = scope.require_bootstrap(&realm).map_err(map_scope_conflict)?;
    if !lane.is_serving() {
        return Err(Error::internal("provisioning classified as a non-serving lane"));
    }
    // A creation retry must preserve a served repository's current HEAD after
    // its first push chose a different branch. Bootstrap still uses the fresh
    // default and a ready binding with no gate remains a corruption refusal.
    let head_ref = if binding.ready() {
        PgRefStoreCore
            .read_gate_in_tx(tx, repository_id, true)
            .await
            .map_err(map_refstore)?
            .ok_or_else(|| Error::internal("ready serving authority has no gate"))?
            .head_ref()
            .clone()
    } else {
        RefName::branch(DEFAULT_HEAD_REF).map_err(map_refstore)?
    };
    let init = CoreGateInit::new(
        repository_id,
        owner_id,
        realm.object_format(),
        realm.history_incarnation(),
        realm.authority_epoch(),
        realm.group_epoch(),
        head_ref,
    )
    .map_err(map_refstore)?;
    let gate = PgRefStoreCore.initialize_in_tx(tx, &init, deadline).await.map_err(map_refstore)?;
    if gate.tenant_id() != owner_id
        || gate.object_format() != realm.object_format()
        || gate.history_incarnation() != realm.history_incarnation()
        || gate.authority_epoch() != realm.authority_epoch()
        || gate.group_epoch() != realm.group_epoch()
    {
        return Err(Error(StatusCode::CONFLICT, "durable core gate differs from the provisioning intent"));
    }
    let expectation = RealmExpectation::new(
        repository_id,
        owner_id,
        realm.object_format(),
        realm.history_incarnation(),
        realm.authority_epoch(),
        realm.group_epoch(),
    )
    .map_err(map_refstore)?;
    PgDecisionProtocol::new().provision_in_tx(tx, &expectation, deadline).await.map_err(map_refstore)?;

    // Serving always requires a real authorization decision and verified-byte
    // publication. Legacy metadata/A4 commits must be fenced before readiness,
    // including the very first push. Exact historical terminals remain readable.
    tx.execute(
        "UPDATE ref_store_core_protocol_repos SET decision_required=true WHERE repository_id=$1",
        &[&repository_id],
    )
    .await
    .map_err(Error::internal)?;

    // 5. Publish readiness only now: binding first (its trigger re-checks the
    //    exact gate + protocol realm), then the repository row (its trigger
    //    requires the binding to be ready). Both triggers are in migration 145.
    if !binding.ready() {
        tx.execute(
            "UPDATE ref_store_serving_repositories SET state='ready' WHERE repository_id=$1 AND state='pending'",
            &[&repository_id],
        )
        .await
        .map_err(Error::internal)?;
    }
    tx.execute(
        "UPDATE repositories SET state='ready'
         WHERE id=$1 AND owner_id=$2 AND state='provisioning' AND storage_backend='pg_refstore'
           AND transition_state='stable'",
        &[&repository_id, &owner_id],
    )
    .await
    .map_err(Error::internal)?;

    // 6. Final in-transaction consistency proof: ready repository + ready
    //    durable binding of this exact realm and live backend + the gate proof
    //    returned above. Anything else makes the whole transaction roll back.
    let scope = LockedScope::lock(tx, repository_id, false)
        .await
        .map_err(map_refstore)?
        .ok_or_else(|| Error::internal("repository row disappeared during provisioning"))?;
    scope.require_serving(owner_id, backend.as_hex()).map_err(map_scope_conflict)?;
    Ok((repository_id, created))
}

/// Resolve one already served `pg_refstore` repository after current
/// authorization.
///
/// `writable` selects the required role/scope (`write` vs `read`) and refuses a
/// read-only token. Authorization runs first (token, RBAC, token scope,
/// repository `ready`); only then is the durable binding, the live gate and the
/// concrete Blob backend identity checked, so an unauthorized caller cannot
/// probe serving state.
///
/// After authorization and before any repository/scope/gate read, the same
/// bounded transaction also reads the cluster authority incarnation. The
/// lookup rolls back and returns no client or transaction. A later serving read
/// capture must prove the identical incarnation before it may materialize
/// (#174).
pub async fn lookup(
    pool: &Pool,
    actor: &Identity,
    owner: &str,
    name: &str,
    writable: bool,
    backend: &crate::blob_store::BlobBackendIdentity,
    deadline: Instant,
) -> Result<ServingRepository, Error> {
    if !db::valid_name(owner) || !db::valid_name(name) {
        return Err(Error::not_found());
    }
    if writable {
        auth::writable(actor)?;
    }
    let mut client = acquire(pool, deadline).await?;
    let tx = begin_owned(&mut client, deadline).await?;
    let result = lookup_in_tx(&tx, actor, owner, name, writable, backend, deadline).await;
    let _ = tx.rollback().await;
    result
}

pub(crate) async fn lookup_in_tx(
    tx: &Transaction<'_>,
    actor: &Identity,
    owner: &str,
    name: &str,
    writable: bool,
    backend: &crate::blob_store::BlobBackendIdentity,
    deadline: Instant,
) -> Result<ServingRepository, Error> {
    bound(tx, deadline).await.map_err(map_refstore)?;
    let (min_role, action) =
        if writable { (Role::Write, RepoAction::ContentsWrite) } else { (Role::Read, RepoAction::ContentsRead) };
    let access = auth::authorize_repo_with_role(tx, actor, owner, name, min_role, action).await?;
    // Only an authorized caller reads the restore incarnation, as the first
    // shared-lock statement after auth and inside this same read-only `tx`
    // (every later read, including `LockedScope::lock`, reuses it; none opens
    // another transaction). `NOWAIT` is required: auth already holds
    // tokens/users/repository `FOR SHARE` and `backup::authority::fence` updates
    // the cluster row before its token rows, so a *blocking* cluster
    // `FOR SHARE` here could deadlock (token->cluster vs cluster->token). Only
    // this one read maps a contended lock locally; every other failure (and
    // every other DB read) keeps the shared deadline policy.
    let cluster_incarnation = map_cluster_incarnation(read_cluster_incarnation_nowait(tx).await)?;
    // The tenant identity is the owner namespace resolved by that
    // authorization, never the actor id.
    let scope =
        LockedScope::lock(tx, access.repo_id, false).await.map_err(map_refstore)?.ok_or_else(Error::not_found)?;
    let binding = scope.require_serving(access.owner_id, backend.as_hex()).map_err(map_scope_refusal)?;
    let gate = PgRefStoreCore
        .read_gate_in_tx(tx, access.repo_id, false)
        .await
        .map_err(map_refstore)?
        .ok_or_else(Error::not_found)?;
    // Durable binding realm must equal the live gate realm; a gate that moved
    // under another realm is a durable inconsistency, never a request verdict.
    scope.require_binding_matches_gate(&gate).map_err(|refusal| Error::internal(refusal.reason()))?;
    if gate.tenant_id() != access.owner_id
        || gate.object_format() != binding.object_format()
        || gate.repository_id() != access.repo_id
    {
        return Err(Error::internal("durable gate/binding realm mismatch"));
    }
    let repository = read_repository_in_tx(tx, access.repo_id).await?;
    Ok(ServingRepository { repository, gate, cluster_incarnation })
}

/// The generic, retryable refusal for a cluster-anchor lock that `NOWAIT`
/// could not take. It names no SQLSTATE, detail or incarnation.
const NOWAIT_CONTENDED: &str = "ref-store authority is busy; retry the same request";

/// Outcome of the cluster anchor `FOR SHARE NOWAIT`: either the incarnation was
/// read, or the lock was held by another transaction. Any other failure is
/// returned unchanged (and therefore mapped by the caller's shared mapper).
enum ClusterIncarnation {
    Read(Uuid),
    LockNotAvailable,
}

/// Lock and read the global restore incarnation (migration 085) `FOR SHARE NOWAIT`
/// in the caller's already-authorized transaction. Exactly one non-nil
/// singleton row is required; anything else is a typed store failure, never an
/// empty anchor.
async fn read_cluster_incarnation_nowait(tx: &Transaction<'_>) -> Result<ClusterIncarnation, RefStoreError> {
    let rows = match tx
        .query("SELECT incarnation FROM public.cluster_authority WHERE singleton=true FOR SHARE NOWAIT", &[])
        .await
    {
        Ok(rows) => rows,
        Err(error) if nowait_contended(&error) => return Ok(ClusterIncarnation::LockNotAvailable),
        Err(error) => return Err(crate::ref_store::pg::db_error(error)),
    };
    let [row] = rows.as_slice() else {
        return Err(RefStoreError::Database(format!(
            "cluster authority has {} singleton incarnation rows, expected exactly one",
            rows.len()
        )));
    };
    let incarnation: Uuid = row
        .try_get(0)
        .map_err(|_| RefStoreError::Database("cluster authority row has no uuid incarnation".into()))?;
    if incarnation.is_nil() {
        return Err(RefStoreError::Database("cluster authority incarnation is nil".into()));
    }
    Ok(ClusterIncarnation::Read(incarnation))
}

/// `SQLSTATE 55P03` (`lock_not_available`): the `NOWAIT` share lock was not
/// taken, nothing was written, and retrying the same statement is the remedy.
fn nowait_contended(error: &tokio_postgres::Error) -> bool {
    error.code() == Some(&tokio_postgres::error::SqlState::LOCK_NOT_AVAILABLE)
}

/// Map the cluster anchor outcome: only this lookup's contended `NOWAIT` becomes
/// the generic retryable service error; everything else keeps the shared mapper.
fn map_cluster_incarnation(outcome: Result<ClusterIncarnation, RefStoreError>) -> Result<Uuid, Error> {
    match outcome {
        Ok(ClusterIncarnation::Read(incarnation)) => Ok(incarnation),
        Ok(ClusterIncarnation::LockNotAvailable) => Err(Error(StatusCode::SERVICE_UNAVAILABLE, NOWAIT_CONTENDED)),
        Err(error) => Err(map_refstore(error)),
    }
}

async fn read_repository(pool: &Pool, repository_id: Uuid, deadline: Instant) -> Result<Repository, Error> {
    let client = acquire(pool, deadline).await?;
    let row = tokio::time::timeout_at(
        deadline,
        client.query_opt(&format!("{} WHERE r.id=$1", db::REPO_SELECT), &[&repository_id]),
    )
    .await
    .map_err(|_| deadline_error())?
    .map_err(Error::internal)?
    .ok_or_else(Error::not_found)?;
    Ok(Repository::from_row(&row))
}

async fn read_repository_in_tx(tx: &Transaction<'_>, repository_id: Uuid) -> Result<Repository, Error> {
    let row = tx
        .query_opt(&format!("{} WHERE r.id=$1", db::REPO_SELECT), &[&repository_id])
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    Ok(Repository::from_row(&row))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(username: &str) -> Identity {
        Identity {
            id: Uuid::new_v4(),
            token_id: Uuid::new_v4(),
            username: username.to_owned(),
            read_only: false,
            token_digest: vec![0; 32],
        }
    }

    #[test]
    fn default_owner_is_the_acting_user_namespace() {
        let actor = identity("alice");
        let request = ProvisionRequest { owner: None, name: "demo".into(), object_format: GitObjectFormat::Sha1 };
        let owner = request.owner.clone().unwrap_or_else(|| actor.username.clone());
        assert_eq!(owner, "alice");
        assert!(db::valid_name(&owner) && db::valid_name(&request.name));
        assert!(!db::valid_name("Demo"));
        assert!(!db::valid_name("a/b"));
    }

    #[test]
    fn scope_refusals_do_not_disclose_existence_or_leak_authority() {
        assert_eq!(map_scope_refusal(ScopeRefusal::Tenant).0, StatusCode::NOT_FOUND);
        assert_eq!(map_scope_refusal(ScopeRefusal::MissingBinding).0, StatusCode::NOT_FOUND);
        assert_eq!(map_scope_refusal(ScopeRefusal::NotServing).0, StatusCode::NOT_FOUND);
        assert_eq!(map_scope_refusal(ScopeRefusal::BackendIdentity).0, StatusCode::CONFLICT);
        assert_eq!(map_scope_refusal(ScopeRefusal::LegacyAuthority).0, StatusCode::NOT_FOUND);
        assert_eq!(map_scope_conflict(ScopeRefusal::BackendIdentity).0, StatusCode::CONFLICT);
        assert_eq!(map_scope_conflict(ScopeRefusal::Inconsistent("x")).0, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn refstore_errors_map_to_retryable_or_terminal_statuses() {
        assert_eq!(map_refstore(RefStoreError::Timeout).0, StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(
            map_refstore(RefStoreError::CommitUnknown { repository_id: Uuid::new_v4(), operation_id: None }).0,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(map_refstore(RefStoreError::GateConflict).0, StatusCode::CONFLICT);
        assert_eq!(map_refstore(RefStoreError::RepositoryNotFound).0, StatusCode::NOT_FOUND);
    }

    #[test]
    fn only_the_cluster_nowait_contention_is_a_generic_retryable_503() {
        let incarnation = Uuid::new_v4();
        assert_eq!(map_cluster_incarnation(Ok(ClusterIncarnation::Read(incarnation))).expect("read"), incarnation);
        let contended = map_cluster_incarnation(Ok(ClusterIncarnation::LockNotAvailable)).expect_err("503");
        assert_eq!(contended.0, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(contended.1, NOWAIT_CONTENDED);
        // Every other failure keeps the shared mapper: a deadline is still the
        // provisioning GATEWAY_TIMEOUT and an internal store failure is never
        // disclosed.
        let timed_out = map_cluster_incarnation(Err(RefStoreError::Timeout)).expect_err("deadline");
        assert_eq!(timed_out.0, StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(timed_out.1, deadline_error().1);
        let missing = RefStoreError::Database("cluster authority incarnation is nil".into());
        let internal = map_cluster_incarnation(Err(missing)).expect_err("internal");
        assert_eq!(internal.0, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(internal.1, "service temporarily unavailable");
    }
}
