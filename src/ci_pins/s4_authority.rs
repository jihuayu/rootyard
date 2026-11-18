//! S4 credential authority shared by the checkout control plane and the Git
//! transport.
//!
//! Every function here is a *live* read. A previously issued plan or closure
//! grant is only ever used as a value to compare against current PostgreSQL
//! facts, never as proof of authority.
use super::s4_models::{GrantExpectation, S4ClosureGrant};
use super::s4_pin::refstore_repository;
use super::*;
use crate::ci_checkouts::{Plan, audience};
use crate::members::{models::Role, rbac};
use crate::ref_store::core::retention_root::{PgRetentionRoots, RootRef};

/// One shared Git slot that returns to the semaphore when the stream ends or is
/// dropped by a client disconnect. The permit is never leaked on an early error.
pub(crate) struct StreamSlot(Option<tokio::sync::OwnedSemaphorePermit>);

impl StreamSlot {
    /// Wrap an already-acquired permit. Used by the unit matrix.
    pub(crate) fn from_permit(permit: tokio::sync::OwnedSemaphorePermit) -> Self {
        Self(Some(permit))
    }

    /// Acquire the shared Git capacity without waiting.
    pub(crate) fn acquire(state: &AppState) -> Result<Self, Error> {
        state
            .git_slots
            .clone()
            .try_acquire_owned()
            .map(Self::from_permit)
            .map_err(|_| Error(StatusCode::SERVICE_UNAVAILABLE, "Git capacity exhausted; retry later"))
    }
}

impl Drop for StreamSlot {
    fn drop(&mut self) {
        self.0.take();
    }
}

/// True when the caller presented a wide `ryu_` user credential, which is never
/// accepted by the CI data plane.
pub(crate) fn wide_credential(headers: &HeaderMap) -> bool {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.to_ascii_lowercase().contains("ryu_"))
}

/// Column list shared by the two live grant reads.
const GRANT_SELECT: &str = "SELECT g.grant_json, g.expires_unix, g.cancelled, g.revoked, \
     j.plan, j.cancelled, j.revoked, j.expires_unix, r.owner_id, r.state, \
     r.storage_generation, r.object_format, t.user_id, ua.username, j.job_id, j.issuer_token_id \
     FROM s4_ci_retention.closure_grants g \
     JOIN ci_checkout_jobs j ON j.repository_id=g.repository_id AND j.job_id=g.job_id \
     JOIN repositories r ON r.id=g.repository_id \
     JOIN tokens t ON t.id=j.issuer_token_id \
     JOIN users ua ON ua.id=t.user_id \
     WHERE g.repository_id=$1 AND g.credential_digest=$2 AND r.name=$3 \
       AND NOT t.revoked AND NOT t.read_only \
       AND (t.expires_at IS NULL OR t.expires_at > clock_timestamp())";

/// Re-authenticate one `ryj_` credential against the exact repository and the
/// exact requested object id.
pub(crate) async fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
    owner: &str,
    name: &str,
    oid: &str,
) -> Result<(db::Identity, db::Repository, Plan), Error> {
    let (user, token) = auth::credentials_for(headers, super::s4_models::JOB_PREFIX)?;
    if user.as_ref().is_some_and(|value| value != owner) {
        return Err(Error::unauthorized());
    }
    let repo = refstore_repository(state, owner, name)
        .await?
        .ok_or_else(Error::unauthorized)?;
    let digest = db::digest(&token);
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let row = tx
        .query_opt(GRANT_SELECT, &[&repo.id, &digest, &name])
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::unauthorized)?;
    if row.get::<_, bool>(2)
        || row.get::<_, bool>(3)
        || row.get::<_, bool>(5)
        || row.get::<_, bool>(6)
        || row.get::<_, String>(9) != "ready"
        || row.get::<_, i64>(10) != repo.storage_generation
        || row.get::<_, String>(11) != repo.object_format
    {
        return Err(Error::unauthorized());
    }
    let now = now_unix(&tx).await?;
    if row.get::<_, i64>(1) <= now || row.get::<_, i64>(7) <= now {
        return Err(Error::unauthorized());
    }
    let owner_id: Uuid = row.get(8);
    let actor: Uuid = row.get(12);
    if rbac::resolve_effective_role_by_id(&tx, repo.id, owner_id, actor)
        .await?
        .is_none_or(|role| role < Role::Read)
    {
        return Err(Error::unauthorized());
    }
    let grant: S4ClosureGrant = serde_json::from_value(row.get(0)).map_err(|_| Error::unauthorized())?;
    grant.authorize(&GrantExpectation {
        repository_id: repo.id,
        owner_tenant_id: owner_id,
        storage_generation: repo.storage_generation,
        authority_epoch: grant.authority_epoch,
        mirror_audience: audience()?,
        target_oid: oid,
        now_unix: now,
    })?;
    let plan: Plan = serde_json::from_value(row.get(4)).map_err(|_| Error::unauthorized())?;
    if plan.version != 1
        || plan.job_id != row.get::<_, Uuid>(14)
        || plan.repository_id != repo.id
        || plan.owner_id != owner_id
        || plan.target_oid != oid
        || plan.storage_generation != repo.storage_generation
        || plan.mirror_audience != grant.mirror_audience
        || plan.expires_unix != grant.expires_unix
    {
        return Err(Error::unauthorized());
    }
    let root = RootRef::new(repo.id, grant.retention_root_id, 1).map_err(|_| Error::unauthorized())?;
    let record = PgRetentionRoots::root_record_in_tx(&tx, root)
        .await
        .map_err(|_| Error::unauthorized())?;
    if !record.is_some_and(|record| record.is_active()) {
        return Err(Error::unauthorized());
    }
    let pin = tx
        .query_opt(
            "SELECT 1 FROM s4_ci_retention.ci_pins \
             WHERE repository_id=$1 AND job_id=$2 AND state='pinned'",
            &[&repo.id, &plan.job_id],
        )
        .await
        .map_err(Error::internal)?;
    if pin.is_none() {
        return Err(Error::unauthorized());
    }
    tx.commit().await.map_err(Error::internal)?;
    let identity = db::Identity {
        id: actor,
        token_id: row.get(15),
        parent_token_id: None,
        username: row.get(13),
        read_only: true,
        token_digest: digest,
    };
    Ok((identity, repo, plan))
}

/// Interval recheck for one active transfer. A database error must end the
/// stream, so every error path returns `false`.
pub(crate) async fn still_authorized(
    state: &AppState,
    job_id: Uuid,
    credential_digest: &[u8],
    repository_id: Uuid,
    storage_generation: i64,
) -> Result<bool, Error> {
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let row = tx
        .query_opt(
            "SELECT g.retention_root_id, r.owner_id, t.user_id FROM s4_ci_retention.closure_grants g \
             JOIN s4_ci_retention.ci_pins p ON p.repository_id=g.repository_id AND p.job_id=g.job_id \
             JOIN ci_checkout_jobs j ON j.repository_id=g.repository_id AND j.job_id=g.job_id \
             JOIN repositories r ON r.id=g.repository_id \
             JOIN tokens t ON t.id=j.issuer_token_id \
             WHERE g.repository_id=$1 AND g.job_id=$2 AND g.credential_digest=$3 \
               AND p.state='pinned' AND NOT g.cancelled AND NOT g.revoked \
               AND NOT j.cancelled AND NOT j.revoked AND r.state='ready' \
               AND r.owner_id=g.owner_tenant_id AND r.storage_generation=$4 \
               AND NOT t.revoked AND NOT t.read_only \
               AND (t.expires_at IS NULL OR t.expires_at > clock_timestamp()) \
               AND g.expires_unix>extract(epoch FROM clock_timestamp()) \
               AND j.expires_unix>extract(epoch FROM clock_timestamp())",
            &[&repository_id, &job_id, &credential_digest, &storage_generation],
        )
        .await
        .map_err(Error::internal)?;
    let Some(row) = row else {
        return Ok(false);
    };
    let owner_id: Uuid = row.get(1);
    let actor_id: Uuid = row.get(2);
    // Ownership transfer re-reads through RBAC: a role resolved for the old
    // tenant never authorizes a byte after the repository moved.
    let role = rbac::resolve_effective_role_by_id(&tx, repository_id, owner_id, actor_id).await?;
    let authorized = role.is_some_and(|role| role >= Role::Read);
    let root = RootRef::new(repository_id, row.get(0), 1).map_err(|_| Error::internal("bad root"))?;
    let record = PgRetentionRoots::root_record_in_tx(&tx, root)
        .await
        .map_err(|_| Error::internal("root read failed"))?;
    let live = authorized && record.is_some_and(|record| record.is_active());
    let _ = tx.rollback().await;
    Ok(live)
}

async fn now_unix(tx: &deadpool_postgres::Transaction<'_>) -> Result<i64, Error> {
    tx.query_one("SELECT extract(epoch FROM clock_timestamp())::bigint", &[])
        .await
        .map_err(Error::internal)
        .map(|row| row.get(0))
}
