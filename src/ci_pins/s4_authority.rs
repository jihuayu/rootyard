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
use crate::token_scopes::RepoAction;

/// Hard wall-clock bound on one active-transfer revocation recheck.
const RECHECK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// Lock and read `public.cluster_authority.incarnation` (`FOR SHARE NOWAIT`),
/// matching `src/ref_store/serving/authority.rs` deadlock-free lock order.
pub(crate) async fn read_cluster_incarnation_nowait(
    tx: &deadpool_postgres::Transaction<'_>,
) -> Result<Option<uuid::Uuid>, Error> {
    match tx
        .query_opt("SELECT incarnation FROM public.cluster_authority WHERE singleton=true FOR SHARE NOWAIT", &[])
        .await
    {
        Ok(Some(row)) => {
            let inc: uuid::Uuid = row.get(0);
            Ok((!inc.is_nil()).then_some(inc))
        }
        Ok(None) => Ok(None),
        Err(err) if err.code() == Some(&tokio_postgres::error::SqlState::LOCK_NOT_AVAILABLE) => Ok(None),
        Err(err) => Err(Error::internal(err)),
    }
}

pub(crate) async fn require_cluster_incarnation_nowait(
    tx: &deadpool_postgres::Transaction<'_>,
) -> Result<uuid::Uuid, Error> {
    read_cluster_incarnation_nowait(tx).await?.ok_or(Error(
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        "ref-store authority is busy; retry the same request",
    ))
}

/// Re-prove the repository authority and exact generation inside a write tx.
pub(crate) async fn guard_repository(
    tx: &deadpool_postgres::Transaction<'_>,
    actor: &db::Identity,
    owner: &str,
    name: &str,
    repository_id: Uuid,
    tenant_id: Uuid,
    generation: i64,
) -> Result<(), Error> {
    let access =
        auth::authorize_repo_with_role(tx, actor, owner, name, Role::Write, RepoAction::ContentsWrite).await?;
    let row = tx
        .query_one(
            "SELECT owner_id, state, storage_generation FROM repositories WHERE id=$1 FOR SHARE",
            &[&repository_id],
        )
        .await
        .map_err(Error::internal)?;
    if access.repo_id == repository_id
        && row.get::<_, Uuid>(0) == tenant_id
        && row.get::<_, String>(1) == "ready"
        && row.get::<_, i64>(2) == generation
    {
        return Ok(());
    }
    Err(Error(StatusCode::CONFLICT, "repository authority changed"))
}

/// Refuse a reused pin whose retained root is no longer active.
pub(crate) async fn ensure_root_active(
    tx: &deadpool_postgres::Transaction<'_>,
    repository_id: Uuid,
    root_id: Uuid,
) -> Result<(), Error> {
    let root = RootRef::new(repository_id, root_id, 1).map_err(|_| Error::internal("bad root"))?;
    let record = PgRetentionRoots::root_record_in_tx(tx, root)
        .await
        .map_err(|_| Error::internal("root read failed"))?;
    if record.is_some_and(|record| record.is_active()) {
        return Ok(());
    }
    Err(Error(StatusCode::CONFLICT, "retained root unavailable or released"))
}

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

fn is_wide_prefix(value: &str) -> bool {
    value.get(..4).is_some_and(|p| matches!(p.to_ascii_lowercase().as_str(), "ryt_" | "ryu_" | "rys_" | "ryb_"))
}

/// True when the caller presented any wide user/session credential (`ryt_`,
/// `ryu_`, `rys_`, `ryb_`) via `Bearer` or `Basic`, which CI transport forbids.
pub(crate) fn wide_credential(headers: &HeaderMap) -> bool {
    use base64::{Engine as _, engine::general_purpose::{STANDARD, STANDARD_NO_PAD}};
    for raw in headers.get_all(header::AUTHORIZATION) {
        let Ok(text) = raw.to_str() else { continue };
        let Some((scheme, rest)) = text.trim().split_once(' ') else { continue };
        let rest = rest.trim();
        if scheme.eq_ignore_ascii_case("bearer") && is_wide_prefix(rest) {
            return true;
        }
        if scheme.eq_ignore_ascii_case("basic") {
            let decoded = STANDARD.decode(rest).or_else(|_| STANDARD_NO_PAD.decode(rest));
            let Ok(bytes) = decoded else { continue };
            let Ok(pair) = String::from_utf8(bytes) else { continue };
            let wide = match pair.split_once(':') {
                Some((user, pass)) => is_wide_prefix(user) || is_wide_prefix(pass),
                None => is_wide_prefix(&pair),
            };
            if wide {
                return true;
            }
        }
    }
    false
}

/// Column list shared by the two live grant reads.
const GRANT_SELECT: &str = "SELECT g.grant_json, g.expires_unix, g.cancelled, g.revoked, \
     j.plan, j.cancelled, j.revoked, j.expires_unix, r.owner_id, r.state, \
     r.storage_generation, r.object_format, t.user_id, ua.username, j.job_id, j.issuer_token_id, \
     cg.authority_epoch, cg.history_incarnation, cg.group_epoch \
     FROM s4_ci_retention.closure_grants g \
     JOIN ci_checkout_jobs j ON j.repository_id=g.repository_id AND j.job_id=g.job_id \
     JOIN repositories r ON r.id=g.repository_id \
     JOIN ref_store_core_gates cg ON cg.repository_id=g.repository_id AND cg.tenant_id=r.owner_id \
     JOIN ref_store_serving_repositories sr ON sr.repository_id=g.repository_id AND sr.state='ready' \
       AND sr.owner_id=cg.tenant_id AND sr.authority_epoch=cg.authority_epoch \
       AND sr.history_incarnation=cg.history_incarnation AND sr.group_epoch=cg.group_epoch \
     JOIN tokens t ON t.id=j.issuer_token_id \
     JOIN users ua ON ua.id=t.user_id \
     WHERE g.repository_id=$1 AND g.credential_digest=$2 AND r.name=$3 AND g.cluster_incarnation=$4 \
       AND g.authority_epoch=cg.authority_epoch \
       AND g.history_incarnation=cg.history_incarnation \
       AND g.group_epoch=cg.group_epoch \
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
    super::s4_schema::ensure_s4_schema(&state.pool).await?;
    let digest = db::digest(&token);
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let deadline = tokio::time::Instant::now() + state.config.git_timeout;
    crate::ref_store::pg::bound(&tx, deadline).await.map_err(|_| Error::timeout())?;
    let cluster_inc = require_cluster_incarnation_nowait(&tx).await?;
    let row = tx
        .query_opt(GRANT_SELECT, &[&repo.id, &digest, &name, &cluster_inc])
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
        authority_epoch: row.get(16),
        history_incarnation: row.get(17),
        group_epoch: row.get(18),
        cluster_incarnation: cluster_inc,
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
    if !record.is_some_and(|record| {
        record.is_active()
            && record.authority_epoch() == row.get::<_, i64>(16)
            && record.history_incarnation() == row.get::<_, Uuid>(17)
            && record.group_epoch() == row.get::<_, i64>(18)
    }) {
        return Err(Error::unauthorized());
    }
    let pin = tx
        .query_opt(
            "SELECT 1 FROM s4_ci_retention.ci_pins \
             WHERE repository_id=$1 AND job_id=$2 AND state='pinned' \
               AND authority_epoch=$3 AND history_incarnation=$4 AND group_epoch=$5 \
               AND cluster_incarnation=$6",
            &[
                &repo.id,
                &plan.job_id,
                &row.get::<_, i64>(16),
                &row.get::<_, Uuid>(17),
                &row.get::<_, i64>(18),
                &cluster_inc,
            ],
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

/// Interval recheck for one active transfer. A database error or timeout must
/// end the stream, so every error path returns `false`.
pub(crate) async fn still_authorized(
    state: &AppState,
    job_id: Uuid,
    credential_digest: &[u8],
    repository_id: Uuid,
    storage_generation: i64,
) -> Result<bool, Error> {
    let deadline = tokio::time::Instant::now() + RECHECK_TIMEOUT;
    let check = tokio::time::timeout(RECHECK_TIMEOUT, async {
        let mut client = state.pool.get().await.map_err(Error::internal)?;
        let tx = client.transaction().await.map_err(Error::internal)?;
        crate::ref_store::pg::bound(&tx, deadline).await.map_err(|_| Error::timeout())?;
        let Some(cluster_inc) = read_cluster_incarnation_nowait(&tx).await? else {
            return Ok::<bool, Error>(false);
        };
        let row = tx
            .query_opt(
                "SELECT g.retention_root_id, r.owner_id, t.user_id, \
                        cg.authority_epoch, cg.history_incarnation, cg.group_epoch \
                 FROM s4_ci_retention.closure_grants g \
                 JOIN s4_ci_retention.ci_pins p ON p.repository_id=g.repository_id AND p.job_id=g.job_id \
                 JOIN ci_checkout_jobs j ON j.repository_id=g.repository_id AND j.job_id=g.job_id \
                 JOIN repositories r ON r.id=g.repository_id \
                 JOIN ref_store_core_gates cg ON cg.repository_id=g.repository_id AND cg.tenant_id=r.owner_id \
                 JOIN ref_store_serving_repositories sr ON sr.repository_id=g.repository_id AND sr.state='ready' \
                   AND sr.owner_id=cg.tenant_id AND sr.authority_epoch=cg.authority_epoch \
                   AND sr.history_incarnation=cg.history_incarnation AND sr.group_epoch=cg.group_epoch \
                 JOIN tokens t ON t.id=j.issuer_token_id \
                 WHERE g.repository_id=$1 AND g.job_id=$2 AND g.credential_digest=$3 \
                   AND p.state='pinned' AND NOT g.cancelled AND NOT g.revoked \
                   AND NOT j.cancelled AND NOT j.revoked AND r.state='ready' \
                   AND r.owner_id=g.owner_tenant_id AND r.storage_generation=$4 \
                   AND g.authority_epoch=cg.authority_epoch AND p.authority_epoch=cg.authority_epoch \
                   AND g.history_incarnation=cg.history_incarnation AND p.history_incarnation=cg.history_incarnation \
                   AND g.group_epoch=cg.group_epoch AND p.group_epoch=cg.group_epoch \
                   AND g.cluster_incarnation=$5 AND p.cluster_incarnation=$5 \
                   AND NOT t.revoked AND NOT t.read_only \
                   AND (t.expires_at IS NULL OR t.expires_at > clock_timestamp()) \
                   AND g.expires_unix>extract(epoch FROM clock_timestamp()) \
                   AND j.expires_unix>extract(epoch FROM clock_timestamp())",
                &[&repository_id, &job_id, &credential_digest, &storage_generation, &cluster_inc],
            )
            .await
            .map_err(Error::internal)?;
        let Some(row) = row else {
            return Ok::<bool, Error>(false);
        };
        let owner_id: Uuid = row.get(1);
        let actor_id: Uuid = row.get(2);
        let epoch: i64 = row.get(3);
        let incarnation: Uuid = row.get(4);
        let group_epoch: i64 = row.get(5);
        let role = rbac::resolve_effective_role_by_id(&tx, repository_id, owner_id, actor_id).await?;
        let authorized = role.is_some_and(|role| role >= Role::Read);
        let root = RootRef::new(repository_id, row.get(0), 1).map_err(|_| Error::internal("bad root"))?;
        let record = PgRetentionRoots::root_record_in_tx(&tx, root)
            .await
            .map_err(|_| Error::internal("root read failed"))?;
        let live = authorized
            && record.is_some_and(|record| {
                record.is_active()
                    && record.authority_epoch() == epoch
                    && record.history_incarnation() == incarnation
                    && record.group_epoch() == group_epoch
            });
        let _ = tx.rollback().await;
        Ok(live)
    })
    .await;
    Ok(matches!(check, Ok(Ok(true))))
}

async fn now_unix(tx: &deadpool_postgres::Transaction<'_>) -> Result<i64, Error> {
    tx.query_one("SELECT extract(epoch FROM clock_timestamp())::bigint", &[])
        .await
        .map_err(Error::internal)
        .map(|row| row.get(0))
}
