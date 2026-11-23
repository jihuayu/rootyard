//! S4 CI Smart HTTP data plane for `pg_refstore` repositories: read-only, one
//! narrow `ryj_` job credential, and every request re-proves the grant, the pin,
//! the retained root, the token and live RBAC before a byte is materialized from
//! a disposable bare repository rebuilt from the verified `.pack`/`.idx` bytes.
use super::s4_models::{GrantExpectation, S4ClosureGrant, fixed_oid};
use super::s4_authority::{still_authorized, wide_credential};
pub(crate) use super::s4_models::refused_want;
use super::s4_pin::refstore_repository;
use super::s4_transport_stream::{Check, upload_pack_body};
use super::*;
use crate::members::{models::Role, rbac};
use crate::ref_store::core::retention_root::{PgRetentionRoots, RootRef};
use axum::{
    body::Body,
    extract::Request,
    http::{StatusCode, header},
    response::Response,
};
use std::{path::Path as FsPath, sync::Arc};
use tokio::time::Instant;

/// A verified, still-live job grant.
#[derive(Clone)]
struct Authorized {
    grant: S4ClosureGrant,
    digest: Vec<u8>,
}

pub(crate) use super::s4_authority::DisposableCiView;

/// Build one independent live-grant probe. Producer and Body each get their own
/// closure so both may run concurrently without sharing mutable state.
fn live_grant_check(
    state: Arc<AppState>,
    grant: S4ClosureGrant,
    digest: Vec<u8>,
) -> impl FnMut() -> Check + Send + 'static {
    move || -> Check {
        let (state, grant, digest) = (state.clone(), grant.clone(), digest.clone());
        Box::pin(async move {
            still_authorized(&state, grant.job_id, &digest, grant.repository_id, grant.storage_generation)
                .await
                .unwrap_or(false)
        })
    }
}

async fn git_dir(
    state: &AppState,
    holder: &DisposableCiView,
    args: &[&str],
    deadline: Instant,
) -> Result<Vec<u8>, Error> {
    super::s4_authority::run_git_dir_bounded(
        &state.config.git,
        Some(holder.path()),
        args,
        deadline,
        || Error(StatusCode::CONFLICT, "retained root could not be materialized"),
        Some(holder.hold()),
    )
    .await
}

fn write_pack(dir: &FsPath, pack_id: Uuid, pack: &[u8], idx: &[u8]) -> Result<(), Error> {
    let base = format!("pack-{pack_id}");
    let packs = dir.join("objects/pack");
    std::fs::create_dir_all(&packs).map_err(Error::internal)?;
    std::fs::write(packs.join(format!("{base}.pack")), pack).map_err(Error::internal)?;
    std::fs::write(packs.join(format!("{base}.idx")), idx).map_err(Error::internal)?;
    Ok(())
}

async fn init_bare(
    state: &AppState,
    holder: &DisposableCiView,
    format: &str,
    deadline: Instant,
) -> Result<(), Error> {
    let object_format = format!("--object-format={format}");
    let target = holder.path().to_str().ok_or_else(|| Error::internal("invalid disposable repo path"))?;
    super::s4_authority::run_git_dir_bounded(
        &state.config.git,
        None,
        &["init", "--bare", "--quiet", &object_format, target],
        deadline,
        || Error::internal("bare repository initialization failed"),
        Some(holder.hold()),
    )
    .await?;
    Ok(())
}

/// Rebuild one exact retained commit as a throwaway bare repository with one ref.
pub(crate) async fn materialize(
    state: &AppState,
    store: &crate::blob_store::opendal::BlobStore,
    repository_id: Uuid,
    root_id: Uuid,
    target_oid: &str,
    deadline: Instant,
) -> Result<DisposableCiView, Error> {
    let roots = PgRetentionRoots::new(store.clone(), state.config.git.clone()).map_err(Error::internal)?;
    let root = RootRef::new(repository_id, root_id, 1).map_err(Error::internal)?;
    let view = roots
        .materialize_serving(&state.pool, root, deadline)
        .await
        .map_err(|_| Error(StatusCode::CONFLICT, "retained root unavailable or released"))?;
    let holder = DisposableCiView::create()?;
    let dir = holder.path().to_path_buf();
    init_bare(state, &holder, view.object_format().as_str(), deadline).await?;
    for pack in view.packs() {
        let bytes = view
            .pack_bytes(pack.pack_id(), deadline)
            .await
            .map_err(|_| Error(StatusCode::CONFLICT, "retained pack unavailable"))?;
        let idx = view
            .idx_bytes(pack.pack_id(), deadline)
            .await
            .map_err(|_| Error(StatusCode::CONFLICT, "retained index unavailable"))?;
        write_pack(&dir, pack.pack_id(), &bytes, &idx)?;
    }
    git_dir(state, &holder, &["config", "uploadpack.allowAnySHA1InWant", "false"], deadline).await?;
    git_dir(state, &holder, &["config", "uploadpack.allowReachableSHA1InWant", "false"], deadline).await?;
    git_dir(state, &holder, &["config", "uploadpack.allowFilter", "false"], deadline).await?;
    git_dir(state, &holder, &["update-ref", "refs/heads/main", target_oid], deadline).await?;
    git_dir(state, &holder, &["symbolic-ref", "HEAD", "refs/heads/main"], deadline).await?;
    git_dir(state, &holder, &["cat-file", "-e", &format!("{target_oid}^{{commit}}")], deadline).await?;
    Ok(holder)
}

/// One exact still-live authorization decision for the requested object id.
async fn authorize(
    state: &AppState,
    headers: &HeaderMap,
    owner: &str,
    name: &str,
    target: &str,
    deadline: Instant,
) -> Result<Authorized, Error> {
    if wide_credential(headers) {
        return Err(Error(StatusCode::FORBIDDEN, "wide user credentials cannot access CI transport"));
    }
    let (_, token) = auth::credentials_for(headers, super::s4_models::JOB_PREFIX)?;
    let repository = refstore_repository(state, owner, name).await?.ok_or_else(Error::not_found)?;
    super::s4_schema::ensure_s4_schema(&state.pool).await?;
    let format = repository.object_format.clone();
    let target = fixed_oid(target, &format)?.to_owned();
    let digest = db::digest(&token);
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    crate::ref_store::pg::bound(&tx, deadline)
        .await
        .map_err(|_| Error::timeout())?;
    let cluster_inc = super::s4_authority::require_cluster_incarnation_nowait(&tx).await?;
    let row = tx
        .query_opt(
            "SELECT g.grant_json, g.expires_unix, g.revoked, g.cancelled, j.cancelled, j.revoked, \
                    j.expires_unix, r.owner_id, r.state, r.storage_generation, t.user_id, j.job_id, \
                    cg.authority_epoch, cg.history_incarnation, cg.group_epoch \
             FROM s4_ci_retention.closure_grants g \
             JOIN ci_checkout_jobs j ON j.repository_id=g.repository_id AND j.job_id=g.job_id \
             JOIN repositories r ON r.id=g.repository_id \
             JOIN ref_store_core_gates cg ON cg.repository_id=g.repository_id AND cg.tenant_id=r.owner_id \
             JOIN ref_store_serving_repositories sr ON sr.repository_id=g.repository_id AND sr.state='ready' \
               AND sr.owner_id=cg.tenant_id AND sr.authority_epoch=cg.authority_epoch \
               AND sr.history_incarnation=cg.history_incarnation AND sr.group_epoch=cg.group_epoch \
             JOIN tokens t ON t.id=j.issuer_token_id \
             WHERE g.repository_id=$1 AND g.credential_digest=$2 \
               AND g.target_oid=$3 AND r.name=$4 AND g.cluster_incarnation=$5 \
               AND g.authority_epoch=cg.authority_epoch AND g.history_incarnation=cg.history_incarnation \
               AND g.group_epoch=cg.group_epoch",
            &[&repository.id, &digest, &target, &name, &cluster_inc],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::unauthorized)?;
    if row.get::<_, bool>(2)
        || row.get::<_, bool>(3)
        || row.get::<_, bool>(4)
        || row.get::<_, bool>(5)
        || row.get::<_, String>(8) != "ready"
        || row.get::<_, i64>(9) != repository.storage_generation
    {
        return Err(Error::unauthorized());
    }
    let owner_tenant: Uuid = row.get(7);
    let actor: Uuid = row.get(10);
    let now = tx
        .query_one("SELECT extract(epoch FROM clock_timestamp())::bigint", &[])
        .await
        .map_err(Error::internal)?
        .get::<_, i64>(0);
    if row.get::<_, i64>(1) <= now || row.get::<_, i64>(6) <= now {
        return Err(Error::unauthorized());
    }
    let role = rbac::resolve_effective_role_by_id(&tx, repository.id, owner_tenant, actor)
        .await
        .map_err(Error::internal)?;
    if !role.is_some_and(|role| role >= Role::Read) {
        return Err(Error::unauthorized());
    }
    let token_live = tx
        .query_opt(
            "SELECT 1 FROM ci_checkout_jobs j JOIN tokens t ON t.id=j.issuer_token_id \
             WHERE j.repository_id=$1 AND j.job_id=$2 AND NOT t.revoked \
               AND (t.expires_at IS NULL OR t.expires_at>clock_timestamp())",
            &[&repository.id, &row.get::<_, Uuid>(11)],
        )
        .await
        .map_err(Error::internal)?;
    if token_live.is_none() {
        return Err(Error::unauthorized());
    }
    let grant: S4ClosureGrant = serde_json::from_value(row.get(0)).map_err(|_| Error::unauthorized())?;
    grant.authorize(&GrantExpectation {
        repository_id: repository.id,
        owner_tenant_id: owner_tenant,
        storage_generation: repository.storage_generation,
        authority_epoch: row.get(12),
        history_incarnation: row.get(13),
        group_epoch: row.get(14),
        cluster_incarnation: cluster_inc,
        mirror_audience: crate::ci_checkouts::audience()?,
        target_oid: &target,
        now_unix: now,
    })?;
    let pin = tx
        .query_opt(
            "SELECT 1 FROM s4_ci_retention.ci_pins \
             WHERE repository_id=$1 AND job_id=$2 AND state='pinned' \
               AND authority_epoch=$3 AND history_incarnation=$4 AND group_epoch=$5 \
               AND cluster_incarnation=$6",
            &[
                &repository.id,
                &grant.job_id,
                &row.get::<_, i64>(12),
                &row.get::<_, Uuid>(13),
                &row.get::<_, i64>(14),
                &cluster_inc,
            ],
        )
        .await
        .map_err(Error::internal)?;
    if pin.is_none() {
        return Err(Error::unauthorized());
    }
    let root = RootRef::new(repository.id, grant.retention_root_id, 1).map_err(Error::internal)?;
    let record = PgRetentionRoots::root_record_in_tx(&tx, root)
        .await
        .map_err(|_| Error::unauthorized())?;
    if !record.is_some_and(|record| {
        record.is_active()
            && record.authority_epoch() == row.get::<_, i64>(12)
            && record.history_incarnation() == row.get::<_, Uuid>(13)
            && record.group_epoch() == row.get::<_, i64>(14)
    }) {
        return Err(Error::unauthorized());
    }
    let _ = tx.rollback().await;
    Ok(Authorized { grant, digest })
}

fn advertisement(service: &str, refs: &[u8]) -> Vec<u8> {
    let line = format!("# service=git-{service}\n");
    let mut body = format!("{:04x}", line.len() + 4).into_bytes();
    body.extend_from_slice(line.as_bytes());
    body.extend_from_slice(b"0000");
    body.extend_from_slice(refs);
    body
}

fn store() -> Result<crate::blob_store::opendal::BlobStore, Error> {
    let profile = crate::blob_store::config::BlobProfile::from_env().map_err(Error::internal)?;
    crate::blob_store::opendal::BlobStore::open(profile).map_err(Error::internal)
}

/// `GET /ci/{target}/git/{owner}/{name}/info/refs`
pub(crate) async fn info_refs(
    State(state): State<Arc<AppState>>,
    Path((target, owner, name)): Path<(String, String, String)>,
    request: Request<Body>,
) -> Result<Response, Error> {
    let (owner, name) = split_name(owner, name);
    if refstore_repository(&state, &owner, &name).await?.is_none() {
        return crate::git_http::handle(state, request).await;
    }
    match request.uri().query() {
        Some("service=git-upload-pack") => {}
        Some(query) if query.contains("service=git-receive-pack") => {
            return Err(Error(StatusCode::FORBIDDEN, "CI transport is read-only"));
        }
        _ => return Err(Error::bad_request()),
    }
    let deadline = Instant::now() + state.config.git_timeout;
    let authorized = authorize(&state, request.headers(), &owner, &name, &target, deadline).await?;
    let holder = materialize(
        &state,
        &store()?,
        authorized.grant.repository_id,
        authorized.grant.retention_root_id,
        &authorized.grant.target_oid,
        deadline,
    )
    .await?;
    let repo_dir = holder.path().to_str().ok_or_else(|| Error::internal("invalid disposable repo path"))?;
    let out = git_dir(&state, &holder, &["upload-pack", "--stateless-rpc", "--advertise-refs", repo_dir], deadline)
        .await?;
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/x-git-upload-pack-advertisement")
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(advertisement("upload-pack", &out)))
        .map_err(Error::internal)
}

/// `POST /ci/{target}/git/{owner}/{name}/git-upload-pack`
pub(crate) async fn upload_pack(
    State(state): State<Arc<AppState>>,
    Path((target, owner, name)): Path<(String, String, String)>,
    request: Request<Body>,
) -> Result<Response, Error> {
    let (owner, name) = split_name(owner, name);
    if refstore_repository(&state, &owner, &name).await?.is_none() {
        return crate::git_http::handle(state, request).await;
    }
    let headers = request.headers().clone();
    let deadline = Instant::now() + state.config.git_timeout;
    let body = axum::body::to_bytes(request.into_body(), 16 * 1024 * 1024)
        .await
        .map_err(|_| Error::bad_request())?;
    let authorized = authorize(&state, &headers, &owner, &name, &target, deadline).await?;
    if refused_want(&body, &authorized.grant.target_oid) {
        return Err(Error(StatusCode::FORBIDDEN, "requested object is outside the granted closure"));
    }
    let holder = materialize(
        &state,
        &store()?,
        authorized.grant.repository_id,
        authorized.grant.retention_root_id,
        &authorized.grant.target_oid,
        deadline,
    )
    .await?;
    let producer_check = live_grant_check(state.clone(), authorized.grant.clone(), authorized.digest.clone());
    let delivery_check = live_grant_check(state.clone(), authorized.grant.clone(), authorized.digest.clone());
    let body = upload_pack_body(&state, holder, body, deadline, producer_check, delivery_check)?;
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/x-git-upload-pack-result")
        .header(header::CACHE_CONTROL, "no-store")
        .body(body)
        .map_err(Error::internal)
}

/// `POST /ci/{target}/git/{owner}/{name}/git-receive-pack` is always refused.
pub(crate) async fn receive_pack(
    State(state): State<Arc<AppState>>,
    Path((_target, owner, name)): Path<(String, String, String)>,
    request: Request<Body>,
) -> Result<Response, Error> {
    let (owner, name) = split_name(owner, name);
    if refstore_repository(&state, &owner, &name).await?.is_none() {
        return crate::git_http::handle(state, request).await;
    }
    Err(Error(StatusCode::FORBIDDEN, "CI transport is read-only"))
}

fn split_name(owner: String, name: String) -> (String, String) {
    let name = name.strip_suffix(".git").unwrap_or(&name).to_owned();
    (owner, name)
}
