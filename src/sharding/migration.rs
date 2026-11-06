//! Source-locked Git bundle transfer and verified, resumable repository placement.
use crate::{AppState, Error, auth::{self, Role}, db, journal, members::audit::record_audit_event,
    sharding::{fencing::read_volume_marker_at, models::{self, REPO_ROUTE_FIELDS, RepoShardRoute, VolumeFenceMarker, conflict, json},
        router::{fetch_node, load_or_init_repo_route}, security::require_operator, transitions,
        transport::{self, DELEGATION_HEADER, ENVELOPE_LIFETIME_SECONDS, Envelope}}};
use axum::{Json, body::Body, extract::{OriginalUri, Path, Query, State}, http::{HeaderMap, StatusCode}, response::Response};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs::{self, File, OpenOptions}, os::unix::fs::OpenOptionsExt, path::{Path as FsPath, PathBuf}, sync::Arc, time::Duration};
use tokio::{io::AsyncWriteExt, process::Command};
use tokio_util::io::ReaderStream;
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationInput {
    target_node_id: String,
    operation_id: Option<Uuid>,
    expected_route_epoch: Option<i64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotQuery { refs_sha256: String, journal_sequence: i64 }

#[derive(Serialize)]
pub struct MigrationReceipt {
    operation_id: Uuid,
    repository_id: Uuid,
    source_node_id: String,
    target_node_id: String,
    refs_sha256: String,
    old_route_epoch: i64,
    new_route_epoch: i64,
    state: &'static str,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotReceipt { operation_id: Uuid, refs_sha256: String, state: String }

async fn git_output(state: &AppState, args: &[&str], timeout: Duration) -> Result<Vec<u8>, Error> {
    let mut command: Command = state.storage.git(&state.config);
    command.args(args);
    let output = tokio::time::timeout(timeout, command.output()).await.map_err(|_| Error::timeout())?
        .map_err(Error::internal)?;
    if !output.status.success() { return Err(conflict("Git bundle or verification failed")); }
    if output.stdout.len() > 16 * 1024 * 1024 { return Err(conflict("repository ref manifest too large")); }
    Ok(output.stdout)
}

async fn refs_digest(state: &AppState, repo: &FsPath) -> Result<String, Error> {
    let path = repo.to_str().ok_or_else(Error::bad_request)?;
    let refs = git_output(state, &["--git-dir", path, "for-each-ref", "--format=%(refname) %(objectname)"], state.config.git_timeout).await?;
    if refs.is_empty() { return Err(conflict("empty repository cannot be replicated as ready")); }
    let head = git_output(state, &["--git-dir", path, "symbolic-ref", "HEAD"], state.config.git_timeout).await?;
    let mut hasher = Sha256::new();
    hasher.update(b"rootyard-shard-refs-v1\0");
    hasher.update(&refs);
    hasher.update(b"HEAD\0");
    hasher.update(&head);
    Ok(hex::encode(hasher.finalize()))
}

async fn configure_target(state: &AppState, repo: &FsPath, repo_id: Uuid) -> Result<(), Error> {
    let path = repo.to_str().ok_or_else(Error::bad_request)?;
    git_output(state, &["--git-dir", path, "config", "--remove-section", "remote.origin"], state.config.git_timeout).await?;
    let max_request = state.config.max_request_bytes.to_string();
    let settings = [
        ("rootyard.repositoryId", repo_id.to_string()),
        ("http.receivepack", "true".into()),
        ("http.getanyfile", "false".into()),
        ("receive.denyNonFastForwards", "true".into()),
        ("receive.denyDeleteCurrent", "true".into()),
        ("receive.fsckObjects", "true".into()),
        ("transfer.fsckObjects", "true".into()),
        ("receive.maxInputSize", max_request),
        ("uploadpack.allowFilter", "false".into()),
        ("uploadpack.allowAnySHA1InWant", "false".into()),
        ("uploadpack.allowTipSHA1InWant", "false".into()),
        ("uploadpack.allowReachableSHA1InWant", "false".into()),
        ("core.logAllRefUpdates", "true".into()),
        ("core.fsync", "committed".into()),
        ("core.fsyncMethod", "fsync".into()),
        ("gc.auto", "0".into()),
        ("maintenance.auto", "false".into()),
        ("pack.threads", "1".into()),
        ("pack.windowMemory", "32m".into()),
        ("pack.deltaCacheSize", "32m".into()),
    ];
    for (name, value) in settings {
        git_output(state, &["--git-dir", path, "config", name, &value], state.config.git_timeout).await?;
    }
    Ok(())
}

fn staging_root(state: &AppState) -> Result<PathBuf, Error> {
    let root = state.storage.root.join("shard-staging");
    fs::create_dir_all(&root).map_err(Error::internal)?;
    let meta = fs::symlink_metadata(&root).map_err(Error::internal)?;
    if !meta.is_dir() || meta.file_type().is_symlink() { return Err(conflict("unsafe shard staging directory")); }
    Ok(root)
}

fn clean_staging(path: &FsPath) -> Result<(), Error> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => fs::remove_dir_all(path).map_err(Error::internal),
        Ok(meta) if meta.is_file() && !meta.file_type().is_symlink() => fs::remove_file(path).map_err(Error::internal),
        Ok(_) => Err(conflict("unsafe existing shard staging path")),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(Error::internal(err)),
    }
}

fn sync_parent(path: &FsPath) -> Result<(), Error> {
    File::open(path).and_then(|f| f.sync_all()).map_err(Error::internal)
}

pub async fn migrate_repository(
    State(state): State<Arc<AppState>>, Path((owner, name)): Path<(String, String)>,
    headers: HeaderMap, Json(input): Json<MigrationInput>,
) -> Result<Response, Error> {
    if !models::valid_node_id(&input.target_node_id) { return Err(Error::bad_request()); }
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = auth::authorize_repo_with_role(&tx, &actor, &owner, &name, Role::Admin).await?;
    require_operator(&tx, &actor).await?;
    let route = load_or_init_repo_route(&tx, access.owner_id, access.repo_id).await?;
    let authority_incarnation: Uuid = tx.query_one("SELECT incarnation FROM cluster_authority WHERE singleton=true", &[])
        .await.map_err(Error::internal)?.get(0);
    auth::finish_tx(tx, &actor, false).await?;
    if transport::node_id()?.as_deref() != Some(route.primary_node_id.as_str()) {
        return Err(conflict("migration must run on source storage node"));
    }
    // This lock covers the final snapshot, transfer, and placement commit. A push admitted
    // before it is acquired completes first; later pushes recheck the new route after release.
    let _write_lock = state.storage.write_lock(access.repo_id).await;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    auth::verify_token(&tx, &actor, true).await?;
    require_operator(&tx, &actor).await?;
    let route_sql = format!("SELECT {REPO_ROUTE_FIELDS} FROM repository_shard_routes WHERE repository_id = $1 FOR UPDATE");
    let route = RepoShardRoute::row(&tx.query_one(&route_sql, &[&access.repo_id]).await.map_err(Error::internal)?);
    if route.primary_node_id == input.target_node_id || route.primary_node_id != transport::node_id()?.unwrap_or_default()
        || input.expected_route_epoch.is_some_and(|e| e != route.route_epoch) || route.draining || route.read_only_degraded {
        return Err(conflict("migration source or route epoch changed"));
    }
    if route.read_replica_nodes.contains(&input.target_node_id) && route.replica_watermarks.get(&input.target_node_id).is_some_and(|w| w.verified) {
        return Err(conflict("target is currently serving reads; drain replica first"));
    }
    let target = fetch_node(&tx, &input.target_node_id).await?.ok_or_else(Error::not_found)?;
    if target.status != "healthy" || !target.is_lease_active(models::unix_now()) { return Err(conflict("target storage node unavailable")); }
    transport::validate_endpoint(&target.endpoint)?;
    let repo = state.storage.verify_path(access.repo_id).map_err(Error::internal)?;
    let existing_marker = read_volume_marker_at(&repo)?;
    if existing_marker.as_ref().is_some_and(|m| m.read_only_degraded || m.fenced_epoch >= m.route_epoch) {
        return Err(conflict("source volume is fenced or degraded"));
    }
    transitions::reject_pending(&state, access.repo_id).await?;
    if !journal::pending(&state.storage.root, access.repo_id).map_err(Error::internal)?.is_empty() {
        return Err(conflict("source has pending Git journal operations; reconcile before migration"));
    }
    let journal_sequence = journal::sequence(&state.storage.root, access.repo_id).map_err(Error::internal)?;
    let generation: i64 = tx.query_one("SELECT storage_generation FROM repositories WHERE id = $1 FOR UPDATE", &[&access.repo_id]).await.map_err(Error::internal)?.get(0);
    let operation_id = input.operation_id.unwrap_or_else(Uuid::new_v4);
    let prior = tx.query_opt("SELECT source_node_id, target_node_id, source_route_epoch, state FROM shard_replication_operations WHERE id = $1", &[&operation_id]).await.map_err(Error::internal)?;
    if let Some(row) = prior {
        let source: String = row.get(0);
        let destination: String = row.get(1);
        let epoch: i64 = row.get(2);
        let state: String = row.get(3);
        if source != route.primary_node_id || destination != input.target_node_id || epoch != route.route_epoch || state == "completed" || state == "aborted" {
            return Err(conflict("replication operation cannot resume against changed placement"));
        }
    } else {
        tx.execute("INSERT INTO shard_replication_operations(id, repository_id, source_node_id, target_node_id, source_route_epoch, source_generation, state) VALUES ($1,$2,$3,$4,$5,$6,'copying')",
            &[&operation_id, &access.repo_id, &route.primary_node_id, &input.target_node_id, &route.route_epoch, &generation]).await.map_err(Error::internal)?;
    }
    tx.commit().await.map_err(Error::internal)?;
    // No database transaction remains open while native Git and network IO run.
    let stage = staging_root(&state)?;
    let bundle = stage.join(format!("{operation_id}.bundle"));
    clean_staging(&bundle)?;
    git_output(&state, &["--git-dir", repo.to_str().ok_or_else(Error::bad_request)?, "fsck", "--full", "--strict"], state.config.git_timeout).await?;
    git_output(&state, &["--git-dir", repo.to_str().ok_or_else(Error::bad_request)?, "bundle", "create", bundle.to_str().ok_or_else(Error::bad_request)?, "--all"], state.config.git_timeout).await?;
    File::open(&bundle).and_then(|f| f.sync_all()).map_err(Error::internal)?;
    sync_parent(&stage)?;
    let digest = refs_digest(&state, &repo).await?;
    let path = format!("/internal/shards/{}/snapshot/{}?refs_sha256={digest}&journal_sequence={journal_sequence}", access.repo_id, operation_id);
    let envelope = Envelope {
        version: 1, authority_incarnation, nonce: Uuid::new_v4(), expires_unix: models::unix_now() + ENVELOPE_LIFETIME_SECONDS,
        actor_id: actor.id, token_id: actor.token_id, repository_id: access.repo_id,
        target_node_id: input.target_node_id.clone(), route_epoch: route.route_epoch,
        fencing_token: route.fencing_token, storage_generation: generation,
        method: "POST".into(), path_and_query: path.clone(),
    };
    let mut url = transport::validate_endpoint(&target.endpoint)?;
    url.set_path(path.split('?').next().unwrap_or("/"));
    url.set_query(Some(&format!("refs_sha256={digest}&journal_sequence={journal_sequence}")));
    let file = tokio::fs::File::open(&bundle).await.map_err(Error::internal)?;
    let http = transport::cluster_client(state.config.git_timeout)?;
    let upstream = http.post(url).header(DELEGATION_HEADER, transport::sign(&envelope)?)
        .body(reqwest::Body::wrap_stream(ReaderStream::new(file))).send().await
        .map_err(|_| Error(StatusCode::BAD_GATEWAY, "replica transfer interrupted"))?;
    if upstream.status() != StatusCode::OK { return Err(conflict("replica rejected snapshot transfer")); }
    let receipt: SnapshotReceipt = upstream.json().await.map_err(Error::internal)?;
    if receipt.operation_id != operation_id || receipt.refs_sha256 != digest || receipt.state != "verified" {
        return Err(conflict("target snapshot verification receipt mismatch"));
    }
    clean_staging(&bundle)?;

    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let current_incarnation: Uuid = tx.query_one("SELECT incarnation FROM cluster_authority WHERE singleton=true", &[])
        .await.map_err(Error::internal)?.get(0);
    if current_incarnation != authority_incarnation { return Err(conflict("metadata authority changed during transfer")); }
    auth::verify_token(&tx, &actor, true).await?;
    require_operator(&tx, &actor).await?;
    let confirmed = tx.query_opt("SELECT refs_sha256 FROM shard_replication_operations WHERE id = $1 AND repository_id = $2 AND state = 'verified' FOR UPDATE",
        &[&operation_id, &access.repo_id]).await.map_err(Error::internal)?;
    if confirmed.as_ref().map(|r| r.get::<_, String>(0)) != Some(digest.clone()) { return Err(conflict("replica verification state missing")); }
    let route = RepoShardRoute::row(&tx.query_one(&route_sql, &[&access.repo_id]).await.map_err(Error::internal)?);
    if route.primary_node_id != transport::node_id()?.unwrap_or_default() {
        return Err(conflict("source placement changed during replication"));
    }
    if route.route_epoch != envelope.route_epoch || route.fencing_token != envelope.fencing_token {
        return Err(conflict("route changed during replication"));
    }
    let new_epoch = route.route_epoch + 1;
    let new_token = route.fencing_token.max(new_epoch) + 1;
    let new_generation = generation + 1;
    auth::authorize_repo_with_role(&tx, &actor, &owner, &name, Role::Admin).await?;
    let updated = tx.execute("UPDATE repositories SET storage_generation = $2 WHERE id = $1 AND storage_generation = $3", &[&access.repo_id, &new_generation, &generation]).await.map_err(Error::internal)?;
    if updated != 1 { return Err(conflict("repository generation changed during transfer")); }
    tx.execute("UPDATE shard_nodes SET role='primary', lease_epoch=GREATEST(lease_epoch,$2), version=version+1 WHERE node_id=$1", &[&input.target_node_id, &new_epoch]).await.map_err(Error::internal)?;
    let upd = format!("UPDATE repository_shard_routes SET primary_node_id=$2, route_epoch=$3, fencing_token=$4, fenced_epoch=$5, required_generation=$6, explicit_override=true, read_replica_nodes='[]'::jsonb, replica_watermarks='{{}}'::jsonb, version=version+1, updated_at=clock_timestamp() WHERE repository_id=$1 RETURNING {REPO_ROUTE_FIELDS}");
    let moved = RepoShardRoute::row(&tx.query_one(&upd, &[&access.repo_id, &input.target_node_id, &new_epoch, &new_token, &route.route_epoch, &new_generation]).await.map_err(Error::internal)?);
    tx.execute("UPDATE shard_replication_operations SET state='completed', updated_at=clock_timestamp() WHERE id=$1 AND state='verified'", &[&operation_id]).await.map_err(Error::internal)?;
    let marker = VolumeFenceMarker::from_route(&moved, new_generation, Some(route.primary_node_id.clone()), models::unix_now());
    record_audit_event(&tx, access.owner_id, access.repo_id, &actor, "shard.migrated", "shard_replication", &input.target_node_id,
        serde_json::json!({"operation_id": operation_id, "refs_sha256": digest, "source": route.primary_node_id, "target": input.target_node_id})).await?;
    let transition_id = transitions::stage(&tx, &state, &marker).await?;
    transitions::commit_and_publish(&state, tx, &actor, &marker, transition_id).await?;
    Ok(json(StatusCode::OK, MigrationReceipt { operation_id, repository_id: access.repo_id, source_node_id: route.primary_node_id,
        target_node_id: input.target_node_id, refs_sha256: digest, old_route_epoch: route.route_epoch, new_route_epoch: new_epoch, state: "completed" }))
}

pub async fn receive_snapshot(
    State(state): State<Arc<AppState>>, Path((repo_id, op_id)): Path<(Uuid, Uuid)>,
    Query(query): Query<SnapshotQuery>, OriginalUri(uri): OriginalUri, headers: HeaderMap, body: Body,
) -> Result<Response, Error> {
    if query.refs_sha256.len() != 64 || query.journal_sequence < 0
        || !query.refs_sha256.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) {
        return Err(Error::bad_request());
    }
    if headers.contains_key(axum::http::header::AUTHORIZATION) { return Err(Error::unauthorized()); }
    let raw = headers.get(DELEGATION_HEADER).and_then(|v| v.to_str().ok()).ok_or_else(Error::unauthorized)?;
    let env = transport::verify(raw)?;
    let now = models::unix_now();
    if env.version != 1 || env.nonce.is_nil() || env.expires_unix < now || env.expires_unix > now + ENVELOPE_LIFETIME_SECONDS
        || env.method != "POST" || env.path_and_query != uri.path_and_query().map_or(uri.path(), |p| p.as_str())
        || env.repository_id != repo_id || transport::node_id()?.as_deref() != Some(env.target_node_id.as_str()) {
        return Err(Error::unauthorized());
    }
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let current_incarnation: Uuid = tx.query_one("SELECT incarnation FROM cluster_authority WHERE singleton=true", &[])
        .await.map_err(Error::internal)?.get(0);
    if current_incarnation != env.authority_incarnation { return Err(Error::unauthorized()); }
    let nonce_inserted = tx.execute("INSERT INTO cluster_transport_nonces(nonce,expires_at) VALUES($1,to_timestamp($2::bigint::double precision)) ON CONFLICT DO NOTHING", &[&env.nonce, &env.expires_unix]).await.map_err(Error::internal)?;
    if nonce_inserted != 1 { return Err(Error::unauthorized()); }
    let row = tx.query_opt("SELECT u.username,t.read_only,t.digest FROM tokens t JOIN users u ON u.id=t.user_id WHERE t.id=$1 AND t.user_id=$2 AND NOT t.revoked AND (t.expires_at IS NULL OR t.expires_at > clock_timestamp())",
        &[&env.token_id, &env.actor_id]).await.map_err(Error::internal)?.ok_or_else(Error::unauthorized)?;
    let actor = db::Identity { id: env.actor_id, token_id: env.token_id, username: row.get(0), read_only: row.get(1), token_digest: row.get(2) };
    require_operator(&tx, &actor).await?;
    let repo = tx.query_one("SELECT u.slug,r.name,r.storage_generation,r.owner_id FROM repositories r JOIN namespaces u ON u.id=r.owner_id WHERE r.id=$1", &[&repo_id]).await.map_err(Error::internal)?;
    let owner: String = repo.get(0);
    let name: String = repo.get(1);
    let generation: i64 = repo.get(2);
    let owner_id: Uuid = repo.get(3);
    auth::authorize_repo_with_role(&tx, &actor, &owner, &name, Role::Admin).await?;
    let op = tx.query_opt("SELECT source_node_id,target_node_id,source_route_epoch,source_generation,state FROM shard_replication_operations WHERE id=$1 AND repository_id=$2",
        &[&op_id, &repo_id]).await.map_err(Error::internal)?.ok_or_else(Error::not_found)?;
    let target: String = op.get(1);
    let source: String = op.get(0);
    let epoch: i64 = op.get(2);
    let source_gen: i64 = op.get(3);
    let op_state: String = op.get(4);
    if target != env.target_node_id || epoch != env.route_epoch || source_gen != env.storage_generation || generation != source_gen
        || !matches!(op_state.as_str(), "copying" | "verified") { return Err(conflict("snapshot operation or generation changed")); }
    let route = load_or_init_repo_route(&tx, owner_id, repo_id).await?;
    if route.route_epoch != env.route_epoch || route.fencing_token != env.fencing_token || route.primary_node_id != source {
        return Err(conflict("source placement changed before snapshot transfer"));
    }
    let maximum: i64 = tx.query_one("SELECT COALESCE(MAX(sequence),0) FROM git_operations WHERE repository_id=$1", &[&repo_id]).await.map_err(Error::internal)?.get(0);
    if query.journal_sequence < maximum { return Err(conflict("source journal sequence is behind recorded Git operations")); }
    tx.commit().await.map_err(Error::internal)?;
    let _lock = state.storage.write_lock(repo_id).await;
    let root = staging_root(&state)?;
    let bundle = root.join(format!("{op_id}.incoming.bundle"));
    let staging = root.join(format!("{op_id}.git"));
    clean_staging(&bundle)?;
    clean_staging(&staging)?;
    let file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&bundle).map_err(Error::internal)?;
    let mut file = tokio::fs::File::from_std(file);
    let mut total = 0_u64;
    let mut stream = body.into_data_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(Error::internal)?;
        total = total.saturating_add(chunk.len() as u64);
        if total > state.config.max_repo_bytes { return Err(conflict("snapshot bundle exceeds configured repository size")); }
        file.write_all(&chunk).await.map_err(Error::internal)?;
    }
    file.sync_all().await.map_err(Error::internal)?;
    drop(file);
    if total == 0 { return Err(conflict("empty snapshot bundle")); }
    git_output(&state, &["-c", "core.hooksPath=/dev/null", "clone", "--mirror", "--", bundle.to_str().ok_or_else(Error::bad_request)?, staging.to_str().ok_or_else(Error::bad_request)?], state.config.git_timeout).await?;
    git_output(&state, &["--git-dir", staging.to_str().ok_or_else(Error::bad_request)?, "fsck", "--full", "--strict"], state.config.git_timeout).await?;
    let measured = refs_digest(&state, &staging).await?;
    if measured != query.refs_sha256 { return Err(conflict("target refs differ from source snapshot")); }
    configure_target(&state, &staging, repo_id).await?;
    let stage_sync = staging.clone();
    tokio::task::spawn_blocking(move || crate::storage::sync_tree(&stage_sync)).await.map_err(Error::internal)?.map_err(Error::internal)?;
    let journal_root = state.storage.root.join("journal");
    journal::mkdir(&journal_root).map_err(Error::internal)?;
    let journal_repo = journal_root.join(repo_id.to_string());
    journal::mkdir(&journal_repo).map_err(Error::internal)?;
    let current_sequence = journal::sequence(&state.storage.root, repo_id).map_err(Error::internal)?;
    if current_sequence > query.journal_sequence { return Err(conflict("destination journal sequence is ahead of transferred snapshot")); }
    journal::atomic(&journal_repo.join("sequence"), query.journal_sequence.to_string().as_bytes(), true).map_err(Error::internal)?;
    let client = state.pool.get().await.map_err(Error::internal)?;
    let updated = client.execute("UPDATE shard_replication_operations SET state='verified', refs_sha256=$2, updated_at=clock_timestamp() WHERE id=$1 AND state IN ('copying','verified')",
        &[&op_id, &measured]).await.map_err(Error::internal)?;
    if updated != 1 { return Err(conflict("snapshot operation changed before publication")); }
    let final_path = state.storage.repo_path(repo_id);
    let backup = root.join(format!("{op_id}.previous-{}.git", Uuid::new_v4()));
    let had_previous = match fs::symlink_metadata(&final_path) {
        Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => true,
        Ok(_) => return Err(conflict("unsafe existing target repository")),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => false,
        Err(err) => return Err(Error::internal(err)),
    };
    if had_previous { fs::rename(&final_path, &backup).map_err(Error::internal)?; }
    if let Err(error) = fs::rename(&staging, &final_path) {
        if had_previous { fs::rename(&backup, &final_path).map_err(Error::internal)?; }
        return Err(Error::internal(error));
    }
    if let Err(error) = sync_parent(final_path.parent().ok_or_else(Error::bad_request)?) {
        let failed = root.join(format!("{op_id}.failed-{}.git", Uuid::new_v4()));
        fs::rename(&final_path, &failed).map_err(Error::internal)?;
        if had_previous { fs::rename(&backup, &final_path).map_err(Error::internal)?; }
        let _ = clean_staging(&failed);
        return Err(error);
    }
    // A failed cleanup leaves a private staging copy, never a false transfer failure.
    let _ = clean_staging(&backup);
    let _ = clean_staging(&bundle);
    Ok(json(StatusCode::OK, SnapshotReceipt { operation_id: op_id, refs_sha256: measured, state: "verified".into() }))
}
