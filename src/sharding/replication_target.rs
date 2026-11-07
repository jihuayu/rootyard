//! Internal snapshot/delta receivers. A replica is marked verified only after
//! it installed the exact source manifest, passed native fsck and measured a
//! matching ref digest while holding its own exclusive data barrier.
use crate::{
    AppState, Error, auth, db, journal,
    sharding::{
        models::{self, REPO_ROUTE_FIELDS, RepoShardRoute, conflict, json},
        replication::{self, FrameReader},
        router::load_or_init_repo_route,
        security::require_operator,
        transport::{self, DELEGATION_HEADER, ENVELOPE_LIFETIME_SECONDS, Envelope},
    },
};
use axum::{
    body::Body,
    extract::{OriginalUri, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path as FsPath, sync::Arc};
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SnapshotQuery {
    refs_sha256: String,
    journal_sequence: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeltaQuery {
    base_refs_sha256: String,
    refs_sha256: String,
    journal_sequence: i64,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct SnapshotReceipt {
    pub(crate) operation_id: Uuid,
    pub(crate) refs_sha256: String,
    pub(crate) state: String,
}

struct TransferAuth {
    actor: db::Identity,
    owner: String,
    name: String,
    owner_id: Uuid,
    generation: i64,
    op_state: String,
    op_digest: Option<String>,
    op_sequence: Option<i64>,
    route: RepoShardRoute,
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[allow(clippy::too_many_arguments)]
async fn authorize_transfer(
    state: &AppState,
    headers: &HeaderMap,
    uri: &axum::http::Uri,
    repo_id: Uuid,
    op_id: Uuid,
    method: &str,
) -> Result<TransferAuth, Error> {
    if headers.contains_key(axum::http::header::AUTHORIZATION) {
        return Err(Error::unauthorized());
    }
    let raw = headers.get(DELEGATION_HEADER).and_then(|value| value.to_str().ok())
        .ok_or_else(Error::unauthorized)?;
    let env = transport::verify(raw)?;
    let now = models::unix_now();
    if env.version != 1 || env.nonce.is_nil() || env.expires_unix < now
        || env.expires_unix > now + ENVELOPE_LIFETIME_SECONDS || env.method != method
        || env.path_and_query != uri.path_and_query().map_or(uri.path(), |path| path.as_str())
        || env.repository_id != repo_id
        || transport::node_id()?.as_deref() != Some(env.target_node_id.as_str())
    {
        return Err(Error::unauthorized());
    }
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let current_incarnation: Uuid = tx
        .query_one("SELECT incarnation FROM cluster_authority WHERE singleton=true", &[])
        .await
        .map_err(Error::internal)?
        .get(0);
    if current_incarnation != env.authority_incarnation {
        return Err(Error::unauthorized());
    }
    let inserted = tx
        .execute(
            "INSERT INTO cluster_transport_nonces(nonce,expires_at) VALUES($1,to_timestamp($2::bigint::double precision)) ON CONFLICT DO NOTHING",
            &[&env.nonce, &env.expires_unix],
        )
        .await
        .map_err(Error::internal)?;
    if inserted != 1 {
        return Err(Error::unauthorized());
    }
    let row = tx
        .query_opt(
            "SELECT u.username,t.read_only,t.digest FROM tokens t JOIN users u ON u.id=t.user_id \
             WHERE t.id=$1 AND t.user_id=$2 AND NOT t.revoked \
             AND (t.expires_at IS NULL OR t.expires_at > clock_timestamp())",
            &[&env.token_id, &env.actor_id],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::unauthorized)?;
    let actor = db::Identity {
        id: env.actor_id,
        token_id: env.token_id,
        username: row.get(0),
        read_only: row.get(1),
        token_digest: row.get(2),
    };
    require_operator(&tx, &actor).await?;
    let repo = tx
        .query_one(
            "SELECT u.slug,r.name,r.storage_generation,r.owner_id FROM repositories r \
             JOIN namespaces u ON u.id=r.owner_id WHERE r.id=$1",
            &[&repo_id],
        )
        .await
        .map_err(Error::internal)?;
    let owner: String = repo.get(0);
    let name: String = repo.get(1);
    let generation: i64 = repo.get(2);
    let owner_id: Uuid = repo.get(3);
    auth::authorize_repo_with_role(&tx, &actor, &owner, &name, auth::Role::Admin).await?;
    let op = tx
        .query_opt(
            "SELECT source_node_id,target_node_id,source_route_epoch,source_generation,state,refs_sha256,journal_sequence \
             FROM shard_replication_operations WHERE id=$1 AND repository_id=$2",
            &[&op_id, &repo_id],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    let source: String = op.get(0);
    let target: String = op.get(1);
    let epoch: i64 = op.get(2);
    let source_generation: i64 = op.get(3);
    let op_state: String = op.get(4);
    let op_digest: Option<String> = op.get(5);
    let op_sequence: Option<i64> = op.get(6);
    if target != env.target_node_id || epoch != env.route_epoch
        || source_generation != env.storage_generation || generation != source_generation
        || !matches!(op_state.as_str(), "copying" | "verified")
    {
        return Err(conflict("snapshot operation or generation changed"));
    }
    let route = load_or_init_repo_route(&tx, owner_id, repo_id).await?;
    if route.route_epoch != env.route_epoch || route.fencing_token != env.fencing_token
        || route.primary_node_id != source
    {
        return Err(conflict("source placement changed before snapshot transfer"));
    }
    tx.commit().await.map_err(Error::internal)?;
    Ok(TransferAuth {
        actor,
        owner,
        name,
        owner_id,
        generation,
        op_state,
        op_digest,
        op_sequence,
        route,
    })
}

async fn maximum_sequence(state: &AppState, repo_id: Uuid) -> Result<i64, Error> {
    let client = state.pool.get().await.map_err(Error::internal)?;
    Ok(client
        .query_one("SELECT COALESCE(MAX(sequence),0) FROM git_operations WHERE repository_id=$1", &[&repo_id])
        .await
        .map_err(Error::internal)?
        .get(0))
}

async fn update_verified(
    state: &AppState,
    repo_id: Uuid,
    op_id: Uuid,
    digest: &str,
    sequence: i64,
) -> Result<(), Error> {
    let client = state.pool.get().await.map_err(Error::internal)?;
    let updated = client
        .execute(
            "UPDATE shard_replication_operations SET state='verified', refs_sha256=$2, journal_sequence=$3, \
             updated_at=clock_timestamp() WHERE id=$1 AND repository_id=$4 AND state IN ('copying','verified')",
            &[&op_id, &digest, &sequence, &repo_id],
        )
        .await
        .map_err(Error::internal)?;
    if updated != 1 {
        return Err(conflict("snapshot operation changed before publication"));
    }
    Ok(())
}

fn validate_target_path(path: &FsPath) -> Result<bool, Error> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => Ok(true),
        Ok(_) => Err(conflict("unsafe existing target repository")),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(Error::internal(err)),
    }
}

pub(crate) async fn receive_snapshot(
    State(state): State<Arc<AppState>>,
    Path((repo_id, op_id)): Path<(Uuid, Uuid)>,
    Query(query): Query<SnapshotQuery>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, Error> {
    if !valid_digest(&query.refs_sha256) || query.journal_sequence < 0 {
        return Err(Error::bad_request());
    }
    let mut frame = FrameReader::new(body);
    let meta = frame.read_meta().await?;
    if meta.final_refs.is_some() {
        return Err(Error::bad_request());
    }
    let _auth = authorize_transfer(&state, &headers, &uri, repo_id, op_id, "POST").await?;
    let stage = replication::staging_root(&state)?;
    let target = super::locks::exclusive(&state, repo_id).await?;
    target.ensure_active()?;
    let bundle = stage.join(format!("{op_id}.incoming.bundle"));
    let staging = stage.join(format!("{op_id}.git"));
    replication::clean_staging(&bundle)?;
    replication::clean_staging(&staging)?;
    let total = frame.write_bundle(&bundle, state.config.max_repo_bytes, false).await?;
    if total == 0 {
        return Err(conflict("empty snapshot bundle"));
    }
    let bundle_path = bundle.to_str().ok_or_else(Error::bad_request)?;
    let staging_path = staging.to_str().ok_or_else(Error::bad_request)?;
    replication::git_output_lease(
        &state,
        &["-c", "core.hooksPath=/dev/null", "clone", "--mirror", "--", bundle_path, staging_path],
        state.config.git_timeout,
        &target.lease,
    )
    .await?;
    target.ensure_active()?;
    replication::apply_manifest(&state, &staging, &meta.base, &target.lease).await?;
    target.ensure_active()?;
    replication::git_output_lease(
        &state,
        &["--git-dir", staging_path, "fsck", "--full", "--strict"],
        state.config.git_timeout,
        &target.lease,
    )
    .await?;
    target.ensure_active()?;
    let measured = replication::refs_digest_lease(&state, &staging, &target.lease).await?;
    if measured != query.refs_sha256 || measured != meta.base.digest() {
        return Err(conflict("target refs differ from source snapshot"));
    }
    replication::configure_target(&state, &staging, repo_id).await?;
    target.ensure_active()?;
    let sync_stage = staging.clone();
    tokio::task::spawn_blocking(move || crate::storage::sync_tree(&sync_stage))
        .await
        .map_err(Error::internal)?
        .map_err(Error::internal)?;
    let journal_root = state.storage.root.join("journal");
    journal::mkdir(&journal_root).map_err(Error::internal)?;
    let journal_repo = journal_root.join(repo_id.to_string());
    journal::mkdir(&journal_repo).map_err(Error::internal)?;
    let current_sequence = journal::sequence(&state.storage.root, repo_id).map_err(Error::internal)?;
    if current_sequence > query.journal_sequence {
        return Err(conflict("destination journal sequence is ahead of transferred snapshot"));
    }
    target.ensure_active()?;
    journal::atomic(&journal_repo.join("sequence"), query.journal_sequence.to_string().as_bytes(), true)
        .map_err(Error::internal)?;
    update_verified(&state, repo_id, op_id, &measured, query.journal_sequence).await?;
    target.ensure_active()?;
    let final_path = state.storage.repo_path(repo_id);
    let backup = stage.join(format!("{op_id}.previous-{}.git", Uuid::new_v4()));
    let had_previous = validate_target_path(&final_path)?;
    if had_previous {
        fs::rename(&final_path, &backup).map_err(Error::internal)?;
    }
    if let Err(error) = fs::rename(&staging, &final_path) {
        if had_previous {
            fs::rename(&backup, &final_path).map_err(Error::internal)?;
        }
        return Err(Error::internal(error));
    }
    if let Err(error) = replication::sync_parent(final_path.parent().ok_or_else(Error::bad_request)?)
        .and_then(|_| target.ensure_active())
    {
        let failed = stage.join(format!("{op_id}.failed-{}.git", Uuid::new_v4()));
        fs::rename(&final_path, &failed).map_err(Error::internal)?;
        if had_previous {
            fs::rename(&backup, &final_path).map_err(Error::internal)?;
        }
        let _ = replication::clean_staging(&failed);
        return Err(error);
    }
    let _ = replication::clean_staging(&backup);
    let _ = replication::clean_staging(&bundle);
    Ok(json(StatusCode::OK, SnapshotReceipt {
        operation_id: op_id,
        refs_sha256: measured,
        state: "verified".into(),
    }))
}

pub(crate) async fn receive_delta(
    State(state): State<Arc<AppState>>,
    Path((repo_id, op_id)): Path<(Uuid, Uuid)>,
    Query(query): Query<DeltaQuery>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, Error> {
    if !valid_digest(&query.base_refs_sha256) || !valid_digest(&query.refs_sha256)
        || query.journal_sequence < 0
    {
        return Err(Error::bad_request());
    }
    let mut frame = FrameReader::new(body);
    let meta = frame.read_meta().await?;
    let Some(final_refs) = meta.final_refs.as_ref() else {
        return Err(Error::bad_request());
    };
    if meta.base.digest() != query.base_refs_sha256 || final_refs.digest() != query.refs_sha256 {
        return Err(Error::bad_request());
    }
    let auth = authorize_transfer(&state, &headers, &uri, repo_id, op_id, "POST").await?;
    if auth.op_state != "verified" {
        return Err(conflict("delta requires a verified initial snapshot"));
    }
    let maximum = maximum_sequence(&state, repo_id).await?;
    if query.journal_sequence < maximum {
        return Err(conflict("delta watermark is behind acknowledged Git operations"));
    }
    let target = super::locks::exclusive(&state, repo_id).await?;
    target.ensure_active()?;
    let repo = state.storage.verify_path(repo_id).map_err(|_| conflict("target snapshot is missing"))?;
    let path = repo.to_str().ok_or_else(Error::bad_request)?;
    let stage = replication::staging_root(&state)?;
    let bundle = stage.join(format!("{op_id}.incoming.delta.bundle"));
    replication::clean_staging(&bundle)?;
    let total = frame.write_bundle(&bundle, state.config.max_repo_bytes, query.base_refs_sha256 == query.refs_sha256).await?;
    let current = replication::refs_digest_lease(&state, &repo, &target.lease).await?;
    if current == query.refs_sha256 {
        if total != 0 {
            return Err(conflict("unexpected delta bundle for an already current target"));
        }
        replication::git_output_lease(
            &state,
            &["--git-dir", path, "fsck", "--full", "--strict"],
            state.config.git_timeout,
            &target.lease,
        )
        .await?;
    } else {
        if auth.op_digest.as_deref() != Some(query.base_refs_sha256.as_str()) {
            return Err(conflict("target operation is not verified at the delta base"));
        }
        if query.base_refs_sha256 != query.refs_sha256 && total == 0 {
            return Err(conflict("missing delta bundle"));
        }
        if current != query.base_refs_sha256 {
            replication::apply_manifest(&state, &repo, &meta.base, &target.lease).await?;
        }
        target.ensure_active()?;
        if total != 0 {
            let bundle_path = bundle.to_str().ok_or_else(Error::bad_request)?;
            replication::git_output_lease(
                &state,
                &["--git-dir", path, "bundle", "unbundle", bundle_path],
                state.config.git_timeout,
                &target.lease,
            )
            .await?;
        }
        target.ensure_active()?;
        replication::apply_manifest(&state, &repo, final_refs, &target.lease).await?;
        target.ensure_active()?;
        replication::git_output_lease(
            &state,
            &["--git-dir", path, "fsck", "--full", "--strict"],
            state.config.git_timeout,
            &target.lease,
        )
        .await?;
    }
    target.ensure_active()?;
    let measured = replication::refs_digest_lease(&state, &repo, &target.lease).await?;
    if measured != query.refs_sha256 {
        return Err(conflict("target refs differ from the drained source snapshot"));
    }
    let repo_sync = repo.clone();
    tokio::task::spawn_blocking(move || crate::storage::sync_tree(&repo_sync))
        .await
        .map_err(Error::internal)?
        .map_err(Error::internal)?;
    let journal_root = state.storage.root.join("journal");
    journal::mkdir(&journal_root).map_err(Error::internal)?;
    let journal_repo = journal_root.join(repo_id.to_string());
    journal::mkdir(&journal_repo).map_err(Error::internal)?;
    let current_sequence = journal::sequence(&state.storage.root, repo_id).map_err(Error::internal)?;
    if current_sequence > query.journal_sequence {
        return Err(conflict("destination journal is ahead of the drained source"));
    }
    target.ensure_active()?;
    journal::atomic(&journal_repo.join("sequence"), query.journal_sequence.to_string().as_bytes(), true)
        .map_err(Error::internal)?;
    let client = state.pool.get().await.map_err(Error::internal)?;
    let updated = client
        .execute(
            "UPDATE shard_replication_operations SET state='verified', refs_sha256=$2, journal_sequence=$3, \
             updated_at=clock_timestamp() WHERE id=$1 AND repository_id=$4 AND state='verified'",
            &[&op_id, &measured, &query.journal_sequence, &repo_id],
        )
        .await
        .map_err(Error::internal)?;
    if updated != 1 {
        return Err(conflict("snapshot operation changed before delta publication"));
    }
    let _ = replication::clean_staging(&bundle);
    Ok(json(StatusCode::OK, SnapshotReceipt {
        operation_id: op_id,
        refs_sha256: measured,
        state: "verified".into(),
    }))
}
