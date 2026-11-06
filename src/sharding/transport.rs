//! Authenticated, bounded Git data-plane forwarding between disjoint storage nodes.
use crate::{AppState, Error, auth::{self, Role}, db::{self, Identity, Repository}, sharding::{models::{self, REPO_ROUTE_FIELDS, RepoShardRoute, SHARD_NODE_FIELDS, ShardNode, ResolveRouteQuery, conflict}, router::{fetch_node, load_or_init_repo_route, select_route_target}}};
use axum::{body::Body, extract::State, http::{header, HeaderMap, Method, Request, Response, StatusCode, Uri},
    middleware::Next};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_util::StreamExt;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{collections::BTreeMap, io, sync::Arc};
use uuid::Uuid;

pub(crate) const DELEGATION_HEADER: &str = "x-rootyard-cluster-delegation";
pub(crate) const ENVELOPE_LIFETIME_SECONDS: i64 = 30;
type HmacSha256 = Hmac<Sha256>;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Envelope {
    pub(crate) version: u8,
    pub(crate) authority_incarnation: Uuid,
    pub(crate) nonce: Uuid,
    pub(crate) expires_unix: i64,
    pub(crate) actor_id: Uuid,
    pub(crate) token_id: Uuid,
    pub(crate) repository_id: Uuid,
    pub(crate) target_node_id: String,
    pub(crate) route_epoch: i64,
    pub(crate) fencing_token: i64,
    pub(crate) storage_generation: i64,
    pub(crate) method: String,
    pub(crate) path_and_query: String,
}

pub struct RoutePlan {
    endpoint: String,
    envelope: String,
}

fn key() -> Result<Vec<u8>, Error> {
    let encoded = std::env::var("ROOTYARD_CLUSTER_HMAC_KEY")
        .map_err(|_| Error(StatusCode::SERVICE_UNAVAILABLE, "cluster signing key missing"))?;
    let bytes = base64::engine::general_purpose::STANDARD.decode(encoded)
        .map_err(|_| Error(StatusCode::SERVICE_UNAVAILABLE, "cluster signing key invalid"))?;
    if bytes.len() < 32 { return Err(Error(StatusCode::SERVICE_UNAVAILABLE, "cluster signing key too short")); }
    Ok(bytes)
}

pub(crate) fn node_id() -> Result<Option<String>, Error> {
    match std::env::var("ROOTYARD_NODE_ID") {
        Ok(id) if models::valid_node_id(&id) => Ok(Some(id)),
        Ok(_) => Err(Error(StatusCode::SERVICE_UNAVAILABLE, "invalid local cluster node id")),
        Err(_) => Ok(None),
    }
}

/// Provisioning and startup recovery must touch only the assigned data volume.
pub async fn is_local_primary_for_repo(state: &AppState, owner_id: Uuid, repo_id: Uuid) -> Result<bool, Error> {
    let local = node_id()?;
    models::ensure_schema(&state.pool).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    if local.is_none() {
        let count: i64 = tx.query_one("SELECT COUNT(*) FROM shard_nodes", &[]).await.map_err(Error::internal)?.get(0);
        if count > 1 { return Err(conflict("cluster provisioning requires a local node identity")); }
    }
    let route = load_or_init_repo_route(&tx, owner_id, repo_id).await?;
    tx.commit().await.map_err(Error::internal)?;
    Ok(local.as_deref().is_none_or(|node| route.primary_node_id == node))
}

fn path_and_query(uri: &Uri) -> &str { uri.path_and_query().map_or(uri.path(), |v| v.as_str()) }

fn parse_git<'a>(method: &Method, uri: &'a Uri) -> Option<(&'a str, &'a str, bool)> {
    let parts: Vec<_> = uri.path().split('/').collect();
    if !(parts.len() == 5 || parts.len() == 6) || parts[0] != "" || parts[1] != "git" { return None; }
    let owner = parts[2];
    let name = parts[3].strip_suffix(".git")?;
    if !db::valid_name(owner) || !db::valid_name(name) { return None; }
    if parts.len() == 6 && parts[4] == "info" && parts[5] == "refs" && method == Method::GET {
        return match uri.query() {
            Some("service=git-upload-pack") => Some((owner, name, false)),
            Some("service=git-receive-pack") => Some((owner, name, true)),
            _ => None,
        };
    }
    if parts.len() == 5 && method == Method::POST && uri.query().is_none() {
        return match parts[4] {
            "git-upload-pack" => Some((owner, name, false)),
            "git-receive-pack" => Some((owner, name, true)),
            _ => None,
        };
    }
    None
}

struct BrowseRequest<'a> {
    owner: &'a str,
    name: &'a str,
    route_write: bool,
    role_write: bool,
    needs_storage: bool,
}

fn parse_browse<'a>(method: &Method, uri: &'a Uri) -> Option<BrowseRequest<'a>> {
    let parts: Vec<_> = uri.path().split('/').collect();
    if parts.len() < 6 || parts[0..3] != ["", "api", "repos"] { return None; }
    let (owner, name) = (parts[3], parts[4]);
    if !db::valid_name(owner) || !db::valid_name(name) { return None; }
    let tail = &parts[5..];
    let (route_write, role_write, needs_storage) = match (method, tail) {
        (&Method::GET, ["refs" | "commits" | "tree" | "blob" | "compare" | "object-format"]) |
        (&Method::GET, ["commits" | "tree" | "blob", _]) => (false, false, true),
        (&Method::GET, ["storage-route"]) => (false, false, true),
        (&Method::POST, ["ref-transactions"]) |
        (&Method::POST, ["object-format", "drill"]) => (true, true, true),
        (&Method::POST, ["object-format", "negotiate"]) => (true, false, true),
        _ => return None,
    };
    Some(BrowseRequest { owner, name, route_write, role_write, needs_storage })
}

async fn route_browse_request(state: &Arc<AppState>, actor: &Identity,
    method: &Method, uri: &Uri, parsed: &BrowseRequest<'_>) -> Result<Option<RoutePlan>, Error> {
    let local = node_id()?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    if local.is_none() {
        let count: i64 = tx.query_one("SELECT COUNT(*) FROM shard_nodes", &[]).await.map_err(Error::internal)?.get(0);
        if count > 1 { return Err(conflict("cluster browse ingress requires a local node identity")); }
    }
    let access = auth::authorize_repo_with_role(&tx, actor, parsed.owner, parsed.name,
        if parsed.role_write { Role::Write } else { Role::Read }).await?;
    let route = load_or_init_repo_route(&tx, access.owner_id, access.repo_id).await?;
    let generation: i64 = tx.query_one("SELECT storage_generation FROM repositories WHERE id=$1",
        &[&access.repo_id]).await.map_err(Error::internal)?.get(0);
    let primary = fetch_node(&tx, &route.primary_node_id).await?.ok_or_else(|| conflict("primary shard node missing"))?;
    let mut replicas = BTreeMap::new();
    if !parsed.route_write {
        for replica in &route.read_replica_nodes {
            if let Some(node) = fetch_node(&tx, replica).await? { replicas.insert(replica.clone(), node); }
        }
    }
    let selected = select_route_target(&route, generation, &primary, &replicas,
        &ResolveRouteQuery { op: Some(if parsed.route_write { "write" } else { "read" }.into()),
            ..Default::default() })?;
    let authority_incarnation: Uuid = tx.query_one(
        "SELECT incarnation FROM cluster_authority WHERE singleton=true", &[])
        .await.map_err(Error::internal)?.get(0);
    auth::finish_tx(tx, actor, false).await?;
    if local.as_deref().is_none_or(|id| id == selected.target_node_id) { return Ok(None); }
    let env = Envelope {
        version: 1, authority_incarnation, nonce: Uuid::new_v4(),
        expires_unix: models::unix_now() + ENVELOPE_LIFETIME_SECONDS,
        actor_id: actor.id, token_id: actor.token_id, repository_id: access.repo_id,
        target_node_id: selected.target_node_id, route_epoch: selected.route_epoch,
        fencing_token: selected.fencing_token, storage_generation: selected.storage_generation,
        method: method.to_string(), path_and_query: path_and_query(uri).to_string(),
    };
    Ok(Some(RoutePlan { endpoint: selected.target_endpoint, envelope: sign(&env)? }))
}

/// Route-scoped middleware for Git-backed browse and ref-transaction APIs.
/// The destination receives a one-use delegation; handlers receive only the
/// verified actor identity and still perform their own repository checks.
pub async fn browse_middleware(State(state): State<Arc<AppState>>,
    mut request: Request<Body>, next: Next) -> Result<Response<Body>, Error> {
    let method = request.method().clone();
    let uri = request.uri().clone();
    let Some(parsed) = parse_browse(&method, &uri) else { return Err(Error::not_found()); };
    if state.mirror_primary.is_some() {
        if request.headers().contains_key(DELEGATION_HEADER) { return Err(Error::unauthorized()); }
        let actor = auth::authenticate(&state.pool, request.headers()).await?;
        request.extensions_mut().insert(actor);
        return Ok(next.run(request).await);
    }
    let actor = if request.headers().contains_key(DELEGATION_HEADER) {
        authenticate_delegation(&state, request.headers(), &method, &uri)
            .await?.ok_or_else(Error::unauthorized)?.0
    } else {
        let actor = auth::authenticate(&state.pool, request.headers()).await?;
        if parsed.needs_storage
            && let Some(plan) = route_browse_request(&state, &actor, &method, &uri, &parsed).await? {
                return forward_request(&state, plan, request).await;
            }
        actor
    };
    request.extensions_mut().insert(actor);
    Ok(next.run(request).await)
}

pub(crate) fn sign(env: &Envelope) -> Result<String, Error> {
    let payload = serde_json::to_vec(env).map_err(Error::internal)?;
    let mut mac = HmacSha256::new_from_slice(&key()?).map_err(Error::internal)?;
    mac.update(&payload);
    Ok(format!("{}.{}", URL_SAFE_NO_PAD.encode(payload), URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())))
}

pub(crate) fn verify(encoded: &str) -> Result<Envelope, Error> {
    if encoded.len() > 2048 { return Err(Error::unauthorized()); }
    let (payload, tag) = encoded.split_once('.').ok_or_else(Error::unauthorized)?;
    let payload = URL_SAFE_NO_PAD.decode(payload).map_err(|_| Error::unauthorized())?;
    let tag = URL_SAFE_NO_PAD.decode(tag).map_err(|_| Error::unauthorized())?;
    let mut mac = HmacSha256::new_from_slice(&key()?).map_err(Error::internal)?;
    mac.update(&payload);
    mac.verify_slice(&tag).map_err(|_| Error::unauthorized())?;
    serde_json::from_slice(&payload).map_err(|_| Error::unauthorized())
}

/// Returns a forwarding plan only for a valid client Git request routed to another node.
pub fn route_git_request<'a>(state: &'a Arc<AppState>, request: &Request<Body>)
    -> impl std::future::Future<Output = Result<Option<RoutePlan>, Error>> + Send + 'a {
    // The future cannot borrow Body across an await: Axum's request body is not Sync.
    let method = request.method().clone();
    let uri = request.uri().clone();
    let headers = request.headers().clone();
    async move {
    if state.mirror_primary.is_some() || headers.contains_key(DELEGATION_HEADER) { return Ok(None); }
    let Some((owner, name, write)) = parse_git(&method, &uri) else { return Ok(None); };
    let Some(local_node) = node_id()? else {
        let client = state.pool.get().await.map_err(Error::internal)?;
        let count: i64 = client.query_one("SELECT COUNT(*) FROM shard_nodes", &[]).await.map_err(Error::internal)?.get(0);
        if count > 1 { return Err(conflict("cluster Git ingress requires a local node identity")); }
        return Ok(None);
    };
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = auth::authorize_repo_with_role(&tx, &actor, owner, name, if write { Role::Write } else { Role::Read }).await?;
    let authority_incarnation: Uuid = tx.query_one("SELECT incarnation FROM cluster_authority WHERE singleton=true", &[])
        .await.map_err(Error::internal)?.get(0);
    let route = load_or_init_repo_route(&tx, access.owner_id, access.repo_id).await?;
    let repo_generation: i64 = tx.query_one("SELECT storage_generation FROM repositories WHERE id = $1", &[&access.repo_id]).await.map_err(Error::internal)?.get(0);
    let primary = fetch_node(&tx, &route.primary_node_id).await?.ok_or_else(|| conflict("primary shard node missing"))?;
    // Git reads currently use the primary unless a transfer has published a verified watermark.
    let mut replicas = BTreeMap::new();
    for replica in &route.read_replica_nodes {
        if let Some(node) = fetch_node(&tx, replica).await? { replicas.insert(replica.clone(), node); }
    }
    let query = ResolveRouteQuery { op: Some(if write { "write" } else { "read" }.to_string()), ..Default::default() };
    let selected = select_route_target(&route, repo_generation, &primary, &replicas, &query)?;
    auth::finish_tx(tx, &actor, false).await?;
    if selected.target_node_id == local_node { return Ok(None); }
    let env = Envelope {
        version: 1, authority_incarnation, nonce: Uuid::new_v4(), expires_unix: models::unix_now() + ENVELOPE_LIFETIME_SECONDS,
        actor_id: actor.id, token_id: actor.token_id, repository_id: access.repo_id,
        target_node_id: selected.target_node_id, route_epoch: selected.route_epoch,
        fencing_token: selected.fencing_token, storage_generation: selected.storage_generation,
        method: method.to_string(), path_and_query: path_and_query(&uri).to_string(),
    };
    Ok(Some(RoutePlan { endpoint: selected.target_endpoint, envelope: sign(&env)? }))
    }
}

pub(crate) fn validate_endpoint(base: &str) -> Result<reqwest::Url, Error> {
    let url = reqwest::Url::parse(base).map_err(|_| conflict("invalid shard endpoint"))?;
    if url.username() != "" || url.password().is_some() || url.query().is_some() || url.fragment().is_some() || url.path() != "/" {
        return Err(conflict("invalid shard endpoint"));
    }
    let loopback = matches!(url.host_str(), Some("127.0.0.1" | "::1" | "localhost"));
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        return Err(conflict("remote shard endpoint requires HTTPS"));
    }
    Ok(url)
}

pub(crate) fn cluster_client(timeout: std::time::Duration) -> Result<reqwest::Client, Error> {
    let mut builder = reqwest::Client::builder().connect_timeout(std::time::Duration::from_secs(3))
        .timeout(timeout).redirect(reqwest::redirect::Policy::none()).no_proxy();
    if let Ok(ca_path) = std::env::var("ROOTYARD_CLUSTER_CA_PEM") {
        let ca = std::fs::read(ca_path).map_err(Error::internal)?;
        builder = builder.add_root_certificate(reqwest::Certificate::from_pem(&ca).map_err(Error::internal)?);
    }
    builder.build().map_err(Error::internal)
}

pub async fn forward_request(state: &Arc<AppState>, plan: RoutePlan, request: Request<Body>) -> Result<Response<Body>, Error> {
    let mut url = validate_endpoint(&plan.endpoint)?;
    url.set_path(request.uri().path());
    url.set_query(request.uri().query());
    let client = cluster_client(state.config.git_timeout)?;
    let mut outbound = client.request(request.method().clone(), url)
        .header(DELEGATION_HEADER, plan.envelope);
    for h in [header::CONTENT_TYPE, header::CONTENT_ENCODING, header::ACCEPT,
        header::USER_AGENT, header::HeaderName::from_static("idempotency-key")] {
        if let Some(v) = request.headers().get(&h) { outbound = outbound.header(&h, v); }
    }
    if let Some(v) = request.headers().get("git-protocol") { outbound = outbound.header("git-protocol", v); }
    let max_request = state.config.max_request_bytes;
    let stream = async_stream::stream! {
        let mut total = 0_u64;
        let mut body = request.into_body().into_data_stream();
        while let Some(chunk) = body.next().await {
            let chunk = match chunk {
                Ok(chunk) => chunk,
                Err(err) => { yield Err::<bytes::Bytes, io::Error>(io::Error::other(err)); break; }
            };
            total = total.saturating_add(chunk.len() as u64);
            if total > max_request {
                yield Err::<bytes::Bytes, io::Error>(io::Error::other("forwarded Git request exceeds configured limit"));
                break;
            }
            yield Ok::<bytes::Bytes, io::Error>(chunk);
        }
    };
    let upstream = outbound.body(reqwest::Body::wrap_stream(stream)).send().await
        .map_err(|_| Error(StatusCode::BAD_GATEWAY, "shard node unavailable or transport interrupted"))?;
    let status = upstream.status();
    let content_type = upstream.headers().get(header::CONTENT_TYPE).cloned();
    let cache_control = upstream.headers().get(header::CACHE_CONTROL).cloned();
    let mut response = Response::builder().status(status);
    if let Some(v) = content_type { response = response.header(header::CONTENT_TYPE, v); }
    if let Some(v) = cache_control { response = response.header(header::CACHE_CONTROL, v); }
    let max_output = state.config.max_output_bytes;
    let output = async_stream::stream! {
        let mut total = 0_u64;
        let mut body = upstream.bytes_stream();
        while let Some(item) = body.next().await {
            match item {
                Ok(chunk) => {
                    total = total.saturating_add(chunk.len() as u64);
                    if total > max_output {
                        yield Err::<bytes::Bytes, io::Error>(io::Error::other("forwarded Git output exceeds configured limit"));
                        break;
                    }
                    yield Ok::<bytes::Bytes, io::Error>(chunk);
                }
                Err(err) => { yield Err::<bytes::Bytes, io::Error>(io::Error::other(err)); break; }
            }
        }
    };
    response.body(Body::from_stream(output))
        .map_err(Error::internal)
}

/// Data node verifies a one-use delegation and independently rechecks token, RBAC, and placement.
pub async fn authenticate_delegation(state: &Arc<AppState>, headers: &HeaderMap, method: &Method, uri: &Uri) -> Result<Option<(Identity, Repository)>, Error> {
    let Some(value) = headers.get(DELEGATION_HEADER) else { return Ok(None); };
    if headers.contains_key(header::AUTHORIZATION) { return Err(Error::unauthorized()); }
    let env = verify(value.to_str().map_err(|_| Error::unauthorized())?)?;
    let now = models::unix_now();
    if env.version != 1 || env.expires_unix < now || env.expires_unix > now + ENVELOPE_LIFETIME_SECONDS
        || env.method != method.as_str() || env.path_and_query != path_and_query(uri)
        || node_id()?.as_deref() != Some(env.target_node_id.as_str()) {
        return Err(Error::unauthorized());
    }
    let (owner, name, route_write, role_write) = if let Some((owner, name, write)) = parse_git(method, uri) {
        (owner, name, write, write)
    } else {
        let browse = parse_browse(method, uri).filter(|request| request.needs_storage)
            .ok_or_else(Error::not_found)?;
        (browse.owner, browse.name, browse.route_write, browse.role_write)
    };
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let current_incarnation: Uuid = tx.query_one("SELECT incarnation FROM cluster_authority WHERE singleton=true", &[])
        .await.map_err(Error::internal)?.get(0);
    if env.authority_incarnation != current_incarnation { return Err(Error::unauthorized()); }
    let inserted = tx.execute(
        "INSERT INTO cluster_transport_nonces(nonce, expires_at) VALUES ($1, to_timestamp($2::bigint::double precision)) ON CONFLICT DO NOTHING",
        &[&env.nonce, &env.expires_unix],
    ).await.map_err(Error::internal)?;
    if inserted != 1 { return Err(Error::unauthorized()); }
    let row = tx.query_opt(
        "SELECT u.username, t.read_only, t.digest FROM tokens t JOIN users u ON u.id = t.user_id WHERE t.id = $1 AND t.user_id = $2 AND NOT t.revoked AND (t.expires_at IS NULL OR t.expires_at > clock_timestamp())",
        &[&env.token_id, &env.actor_id],
    ).await.map_err(Error::internal)?.ok_or_else(Error::unauthorized)?;
    let actor = Identity { id: env.actor_id, token_id: env.token_id, username: row.get(0), read_only: row.get(1), token_digest: row.get(2) };
    let access = auth::authorize_repo_with_role(&tx, &actor, owner, name,
        if role_write { Role::Write } else { Role::Read }).await?;
    if access.repo_id != env.repository_id { return Err(Error::unauthorized()); }
    // A backend recovery/resolve can advance the repository generation without
    // changing placement or the route epoch. Ingress may have signed this
    // envelope just before that transaction committed. Re-read the authority
    // generation here; route watermarks alone cannot invalidate that request.
    let current_generation: i64 = tx.query_one(
        "SELECT storage_generation FROM repositories WHERE id = $1", &[&access.repo_id],
    ).await.map_err(Error::internal)?.get(0);
    if env.storage_generation != current_generation {
        return Err(conflict("stale delegated storage generation"));
    }
    let route_sql = format!("SELECT {REPO_ROUTE_FIELDS} FROM repository_shard_routes WHERE repository_id = $1");
    let route_row = tx.query_opt(&route_sql, &[&access.repo_id]).await.map_err(Error::internal)?.ok_or_else(|| conflict("repository shard route missing"))?;
    let route = RepoShardRoute::row(&route_row);
    let selected_node = if route_write { &route.primary_node_id } else { &env.target_node_id };
    if selected_node != &env.target_node_id || route.route_epoch != env.route_epoch
        || route.fencing_token != env.fencing_token || route.required_generation > env.storage_generation {
        return Err(conflict("stale delegated shard route"));
    }
    let node_sql = format!("SELECT {SHARD_NODE_FIELDS} FROM shard_nodes WHERE node_id = $1");
    let node = tx.query_opt(&node_sql, &[&env.target_node_id]).await.map_err(Error::internal)?
        .as_ref().map(ShardNode::row).ok_or_else(|| conflict("delegated shard node missing"))?;
    if node.status != "healthy" || !node.is_lease_active(now) { return Err(conflict("delegated shard node unavailable")); }
    if !route_write && env.target_node_id != route.primary_node_id {
        let Some(wm) = route.replica_watermarks.get(&env.target_node_id) else { return Err(conflict("replica has no verified watermark")); };
        if !wm.verified || wm.storage_generation < env.storage_generation || wm.op_sequence < route.required_op_sequence {
            return Err(conflict("replica snapshot is stale"));
        }
    }
    let repo_row = tx.query_one(&format!("{} WHERE r.id=$1", db::REPO_SELECT), &[&access.repo_id]).await.map_err(Error::internal)?;
    let repo = Repository::from_row(&repo_row);
    auth::finish_tx(tx, &actor, false).await?;
    Ok(Some((actor, repo)))
}

/// Metadata restore must rotate the authority before any client traffic resumes.
pub async fn rotate_authority(pool: &deadpool_postgres::Pool) -> anyhow::Result<Uuid> {
    let mut client = pool.get().await?;
    let tx = client.transaction().await?;
    let incarnation: Uuid = tx.query_one(
        "UPDATE cluster_authority SET incarnation=gen_random_uuid(), rotated_at=clock_timestamp() WHERE singleton=true RETURNING incarnation",
        &[],
    ).await?.get(0);
    tx.execute("DELETE FROM cluster_transport_nonces", &[]).await?;
    tx.commit().await?;
    Ok(incarnation)
}
