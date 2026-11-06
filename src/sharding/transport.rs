//! Authenticated, bounded Git data-plane forwarding between disjoint storage nodes.
use crate::{AppState, Error, auth::{self, Role}, db::{self, Identity, Repository}, sharding::{models::{self, REPO_ROUTE_FIELDS, RepoShardRoute, SHARD_NODE_FIELDS, ShardNode, ResolveRouteQuery, conflict}, router::{fetch_node, load_or_init_repo_route, select_route_target}}};
use axum::{body::Body, http::{header, HeaderMap, Method, Request, Response, StatusCode, Uri}};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_util::StreamExt;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{collections::BTreeMap, io, sync::Arc};
use uuid::Uuid;

const DELEGATION_HEADER: &str = "x-rootyard-cluster-delegation";
const ENVELOPE_LIFETIME_SECONDS: i64 = 30;
type HmacSha256 = Hmac<Sha256>;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u8,
    nonce: Uuid,
    expires_unix: i64,
    actor_id: Uuid,
    token_id: Uuid,
    repository_id: Uuid,
    target_node_id: String,
    route_epoch: i64,
    fencing_token: i64,
    storage_generation: i64,
    method: String,
    path_and_query: String,
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

fn node_id() -> Result<Option<String>, Error> {
    match std::env::var("ROOTYARD_NODE_ID") {
        Ok(id) if models::valid_node_id(&id) => Ok(Some(id)),
        Ok(_) => Err(Error(StatusCode::SERVICE_UNAVAILABLE, "invalid local cluster node id")),
        Err(_) => Ok(None),
    }
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

fn sign(env: &Envelope) -> Result<String, Error> {
    let payload = serde_json::to_vec(env).map_err(Error::internal)?;
    let mut mac = HmacSha256::new_from_slice(&key()?).map_err(Error::internal)?;
    mac.update(&payload);
    Ok(format!("{}.{}", URL_SAFE_NO_PAD.encode(payload), URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())))
}

fn verify(encoded: &str) -> Result<Envelope, Error> {
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
    let method = request.method().clone();
    let uri = request.uri().clone();
    let headers = request.headers().clone();
    async move {
    if state.mirror_primary.is_some() || headers.contains_key(DELEGATION_HEADER) { return Ok(None); }
    let Some(local_node) = node_id()? else { return Ok(None); };
    let Some((owner, name, write)) = parse_git(&method, &uri) else { return Ok(None); };
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = auth::authorize_repo_with_role(&tx, &actor, owner, name, if write { Role::Write } else { Role::Read }).await?;
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
        version: 1, nonce: Uuid::new_v4(), expires_unix: models::unix_now() + ENVELOPE_LIFETIME_SECONDS,
        actor_id: actor.id, token_id: actor.token_id, repository_id: access.repo_id,
        target_node_id: selected.target_node_id, route_epoch: selected.route_epoch,
        fencing_token: selected.fencing_token, storage_generation: selected.storage_generation,
        method: method.to_string(), path_and_query: path_and_query(&uri).to_string(),
    };
    Ok(Some(RoutePlan { endpoint: selected.target_endpoint, envelope: sign(&env)? }))
    }
}

fn validate_endpoint(base: &str) -> Result<reqwest::Url, Error> {
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

pub async fn forward_request(state: &Arc<AppState>, plan: RoutePlan, request: Request<Body>) -> Result<Response<Body>, Error> {
    let mut url = validate_endpoint(&plan.endpoint)?;
    url.set_path(request.uri().path());
    url.set_query(request.uri().query());
    let mut builder = reqwest::Client::builder().connect_timeout(std::time::Duration::from_secs(3))
        .timeout(state.config.git_timeout).redirect(reqwest::redirect::Policy::none()).no_proxy();
    if let Ok(ca_path) = std::env::var("ROOTYARD_CLUSTER_CA_PEM") {
        let ca = std::fs::read(ca_path).map_err(Error::internal)?;
        builder = builder.add_root_certificate(reqwest::Certificate::from_pem(&ca).map_err(Error::internal)?);
    }
    let client = builder.build().map_err(Error::internal)?;
    let mut outbound = client.request(request.method().clone(), url)
        .header(DELEGATION_HEADER, plan.envelope);
    for h in [header::CONTENT_TYPE, header::CONTENT_ENCODING, header::ACCEPT, header::USER_AGENT] {
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
    let mut response = Response::builder().status(status);
    if let Some(v) = content_type { response = response.header(header::CONTENT_TYPE, v); }
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
    let (owner, name, write) = parse_git(method, uri).ok_or_else(Error::not_found)?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let inserted = tx.execute(
        "INSERT INTO cluster_transport_nonces(nonce, expires_at) VALUES ($1, to_timestamp($2)) ON CONFLICT DO NOTHING",
        &[&env.nonce, &env.expires_unix],
    ).await.map_err(Error::internal)?;
    if inserted != 1 { return Err(Error::unauthorized()); }
    let row = tx.query_opt(
        "SELECT u.username, t.read_only, t.digest FROM tokens t JOIN users u ON u.id = t.user_id WHERE t.id = $1 AND t.user_id = $2 AND NOT t.revoked AND (t.expires_at IS NULL OR t.expires_at > clock_timestamp())",
        &[&env.token_id, &env.actor_id],
    ).await.map_err(Error::internal)?.ok_or_else(Error::unauthorized)?;
    let actor = Identity { id: env.actor_id, token_id: env.token_id, username: row.get(0), read_only: row.get(1), token_digest: row.get(2) };
    let access = auth::authorize_repo_with_role(&tx, &actor, owner, name, if write { Role::Write } else { Role::Read }).await?;
    if access.repo_id != env.repository_id { return Err(Error::unauthorized()); }
    let route_sql = format!("SELECT {REPO_ROUTE_FIELDS} FROM repository_shard_routes WHERE repository_id = $1");
    let route_row = tx.query_opt(&route_sql, &[&access.repo_id]).await.map_err(Error::internal)?.ok_or_else(|| conflict("repository shard route missing"))?;
    let route = RepoShardRoute::row(&route_row);
    let selected_node = if write { &route.primary_node_id } else { &env.target_node_id };
    if selected_node != &env.target_node_id || route.route_epoch != env.route_epoch
        || route.fencing_token != env.fencing_token || route.required_generation > env.storage_generation {
        return Err(conflict("stale delegated shard route"));
    }
    let node_sql = format!("SELECT {SHARD_NODE_FIELDS} FROM shard_nodes WHERE node_id = $1");
    let node = tx.query_opt(&node_sql, &[&env.target_node_id]).await.map_err(Error::internal)?
        .as_ref().map(ShardNode::row).ok_or_else(|| conflict("delegated shard node missing"))?;
    if node.status != "healthy" || !node.is_lease_active(now) { return Err(conflict("delegated shard node unavailable")); }
    if !write && env.target_node_id != route.primary_node_id {
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
