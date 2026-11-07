//! Online repository migration: pinned initial snapshot, drained delta and
//! fenced cutover. Operation rows make every phase resumable; an operator can
//! abort a drained operation and keep the old primary writable.
use crate::{
    AppState, Error,
    auth::{self, Role, finish_tx as finish},
    members::audit::record_audit_event,
    sharding::{
        faults,
        fencing::read_volume_marker_at,
        locks,
        models::{self, REPO_ROUTE_FIELDS, RepoShardRoute, VolumeFenceMarker, conflict, json, unix_now},
        replication::{self, TransferMeta},
        replication_target::{self, SnapshotReceipt},
        router::{fetch_node, load_or_init_repo_route},
        security::require_operator,
        sidecar, transitions,
        transport::{self, DELEGATION_HEADER, ENVELOPE_LIFETIME_SECONDS, Envelope},
    },
};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use bytes::Bytes;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::json as sjson;
use std::{path::Path as FsPath, sync::Arc};
use tokio_util::io::ReaderStream;
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationInput {
    target_node_id: String,
    operation_id: Option<Uuid>,
    expected_route_epoch: Option<i64>,
    #[serde(default)]
    replicate_only: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AbortInput {
    operation_id: Uuid,
    expected_route_epoch: Option<i64>,
}

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

async fn send_transfer(
    state: &AppState,
    target_url: &str,
    envelope: &Envelope,
    path_and_query: &str,
    meta: &TransferMeta,
    bundle: Option<&FsPath>,
) -> Result<SnapshotReceipt, Error> {
    let mut url = transport::validate_endpoint(target_url)?;
    let (path, query) = path_and_query.split_once('?').ok_or_else(Error::bad_request)?;
    url.set_path(path);
    url.set_query(Some(query));
    let prefix = futures_util::stream::once({
        let bytes = replication::encode_meta(meta)?;
        async move { Ok::<_, std::io::Error>(Bytes::from(bytes)) }
    });
    let reader: Box<dyn tokio::io::AsyncRead + Send + Unpin> = match bundle {
        Some(path) => Box::new(tokio::fs::File::open(path).await.map_err(Error::internal)?),
        None => Box::new(tokio::io::empty()),
    };
    let body = reqwest::Body::wrap_stream(prefix.chain(ReaderStream::new(reader)));
    let http = transport::cluster_client(state.config.git_timeout)?;
    let upstream = http
        .post(url)
        .header(DELEGATION_HEADER, transport::sign(envelope)?)
        .body(body)
        .send()
        .await
        .map_err(|_| Error(StatusCode::BAD_GATEWAY, "replica transfer interrupted"))?;
    if upstream.status() != StatusCode::OK {
        return Err(conflict("replica rejected snapshot transfer"));
    }
    upstream.json::<SnapshotReceipt>().await.map_err(Error::internal)
}

async fn send_sidecar_finalize(
    state: &AppState,
    target_url: &str,
    envelope: &Envelope,
    path: &str,
    operation_id: Uuid,
) -> Result<(), Error> {
    let mut url = transport::validate_endpoint(target_url)?;
    url.set_path(path);
    let http = transport::cluster_client(state.config.git_timeout)?;
    let upstream = http
        .post(url)
        .header(DELEGATION_HEADER, transport::sign(envelope)?)
        .body(Vec::new())
        .send()
        .await
        .map_err(|_| Error(StatusCode::BAD_GATEWAY, "target sidecar finalization interrupted"))?;
    if upstream.status() != StatusCode::OK {
        return Err(conflict("cutover committed but target CI sidecar publication is pending recovery"));
    }
    let receipt = upstream.json::<replication_target::FinalizeReceipt>().await.map_err(Error::internal)?;
    if receipt.operation_id != operation_id || receipt.state != "published" {
        return Err(conflict("target CI sidecar finalization receipt mismatch"));
    }
    Ok(())
}

fn envelope(
    authority_incarnation: Uuid,
    actor: &crate::db::Identity,
    repository_id: Uuid,
    target_node_id: &str,
    route_epoch: i64,
    fencing_token: i64,
    storage_generation: i64,
    path_and_query: String,
) -> Envelope {
    Envelope {
        version: 1,
        authority_incarnation,
        nonce: Uuid::new_v4(),
        expires_unix: unix_now() + ENVELOPE_LIFETIME_SECONDS,
        actor_id: actor.id,
        token_id: actor.token_id,
        repository_id,
        target_node_id: target_node_id.to_owned(),
        route_epoch,
        fencing_token,
        storage_generation,
        method: "POST".into(),
        path_and_query,
    }
}

async fn operation_state(
    state: &AppState,
    repo_id: Uuid,
    operation_id: Uuid,
) -> Result<(String, Option<String>, Option<i64>), Error> {
    let client = state.pool.get().await.map_err(Error::internal)?;
    let row = client
        .query_one(
            "SELECT state, refs_sha256, journal_sequence FROM shard_replication_operations \
             WHERE id=$1 AND repository_id=$2",
            &[&operation_id, &repo_id],
        )
        .await
        .map_err(Error::internal)?;
    Ok((row.get(0), row.get(1), row.get(2)))
}

pub async fn migrate_repository(
    State(state): State<Arc<AppState>>,
    Path((owner, name)): Path<(String, String)>,
    headers: HeaderMap,
    Json(input): Json<MigrationInput>,
) -> Result<Response, Error> {
    if !models::valid_node_id(&input.target_node_id) {
        return Err(Error::bad_request());
    }
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = auth::authorize_repo_with_role(&tx, &actor, &owner, &name, Role::Admin).await?;
    require_operator(&tx, &actor).await?;
    let route = load_or_init_repo_route(&tx, access.owner_id, access.repo_id).await?;
    let authority_incarnation: Uuid = tx
        .query_one("SELECT incarnation FROM cluster_authority WHERE singleton=true", &[])
        .await
        .map_err(Error::internal)?
        .get(0);
    let target = fetch_node(&tx, &input.target_node_id).await?.ok_or_else(Error::not_found)?;
    finish(tx, &actor, false).await?;
    if transport::node_id()?.as_deref() != Some(route.primary_node_id.as_str()) {
        return Err(conflict("migration must run on source storage node"));
    }
    if route.primary_node_id == input.target_node_id {
        return Err(conflict("migration target is already the source primary"));
    }
    if route.read_only_degraded {
        return Err(conflict("migration source is read-only degraded"));
    }
    if target.status != "healthy" || !target.is_lease_active(unix_now()) {
        return Err(conflict("target storage node unavailable"));
    }
    transport::validate_endpoint(&target.endpoint)?;
    let repo = state.storage.verify_path(access.repo_id).map_err(Error::internal)?;
    let existing_marker = read_volume_marker_at(&repo)?;
    if existing_marker
        .as_ref()
        .is_some_and(|marker| marker.read_only_degraded || marker.fenced_epoch >= marker.route_epoch)
    {
        return Err(conflict("source volume is fenced or degraded"));
    }
    transitions::reject_pending(&state, access.repo_id).await?;
    let _migration = locks::migration(&state, access.repo_id).await?;
    let operation_id = input.operation_id.unwrap_or_else(Uuid::new_v4);

    // Persist the operation before moving bytes. A prior attempt can resume
    // only against the exact same source, target, epoch and generation.
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    auth::verify_token(&tx, &actor, true).await?;
    require_operator(&tx, &actor).await?;
    let repository_meta = tx
        .query_one(
            "SELECT storage_generation,object_format FROM repositories WHERE id=$1 FOR UPDATE",
            &[&access.repo_id],
        )
        .await
        .map_err(Error::internal)?;
    let generation: i64 = repository_meta.get(0);
    let object_format: String = repository_meta.get(1);
    if !crate::ci_pins::valid_format(&object_format) {
        return Err(conflict("repository object format is unsupported"));
    }
    // Fail closed on symlinked, non-canonical or foreign-tenant CI sidecars
    // before an operation row or drain exists; the source stays writable.
    sidecar::precheck(&state, access.repo_id, access.owner_id, &object_format, generation)?;
    let route_sql =
        format!("SELECT {REPO_ROUTE_FIELDS} FROM repository_shard_routes WHERE repository_id=$1 FOR UPDATE");
    let route = RepoShardRoute::row(&tx.query_one(&route_sql, &[&access.repo_id]).await.map_err(Error::internal)?);
    if route.primary_node_id != transport::node_id()?.unwrap_or_default()
        || input.expected_route_epoch.is_some_and(|epoch| epoch != route.route_epoch)
        || route.read_only_degraded
    {
        return Err(conflict("migration source or route epoch changed"));
    }
    if route.read_replica_nodes.contains(&input.target_node_id)
        && route.replica_watermarks.get(&input.target_node_id).is_some_and(|watermark| watermark.verified)
    {
        return Err(conflict("target is currently serving reads; drain replica first"));
    }
    let prior = tx
        .query_opt(
            "SELECT source_node_id,target_node_id,source_route_epoch,source_generation,state \
             FROM shard_replication_operations WHERE id=$1",
            &[&operation_id],
        )
        .await
        .map_err(Error::internal)?;
    let mut op_state = if let Some(row) = prior {
        let prior_repo: Uuid = tx
            .query_one("SELECT repository_id FROM shard_replication_operations WHERE id=$1", &[&operation_id])
            .await
            .map_err(Error::internal)?
            .get(0);
        let source: String = row.get(0);
        let destination: String = row.get(1);
        let epoch: i64 = row.get(2);
        let prior_generation: i64 = row.get(3);
        let state: String = row.get(4);
        if prior_repo != access.repo_id
            || source != route.primary_node_id
            || destination != input.target_node_id
            || epoch != route.route_epoch
            || prior_generation != generation
        {
            return Err(conflict("replication operation cannot resume against changed placement"));
        }
        if matches!(state.as_str(), "completed" | "aborted") {
            return Err(conflict("replication operation is already terminal"));
        }
        state
    } else {
        if route.draining {
            return Err(conflict("repository is drained by another migration"));
        }
        tx.execute(
            "INSERT INTO shard_replication_operations(id, repository_id, source_node_id, target_node_id, \
             source_route_epoch, source_generation, state) VALUES ($1,$2,$3,$4,$5,$6,'copying')",
            &[
                &operation_id,
                &access.repo_id,
                &route.primary_node_id,
                &input.target_node_id,
                &route.route_epoch,
                &generation,
            ],
        )
        .await
        .map_err(Error::internal)?;
        "copying".to_owned()
    };
    finish(tx, &actor, true).await?;

    // Phase 1: an initial snapshot can be taken while clients keep writing.
    // Resume from a durable verified copy only when its recorded manifest is
    // present; otherwise replace the standby with a fresh measured snapshot.
    let mut base = replication::read_base(&state, operation_id, access.repo_id)?;
    let (op_digest, _) = {
        let (state_name, digest, _) = operation_state(&state, access.repo_id, operation_id).await?;
        op_state = state_name;
        (digest, ())
    };
    let initial_done = !input.replicate_only
        && op_state == "verified"
        && base.as_ref().is_some_and(|base| {
            op_digest.as_deref() == Some(base.refs_sha256.as_str())
                && base.source_route_epoch == route.route_epoch
                && base.source_generation == generation
        });
    if input.replicate_only && route.draining {
        return Err(conflict("replicate-only requires a writable source route"));
    }
    if !initial_done {
        let snapshot =
            replication::capture_source_snapshot(&state, access.repo_id, operation_id, route.route_epoch, generation)
                .await?;
        let path = format!(
            "/internal/shards/{}/snapshot/{}?refs_sha256={}&journal_sequence={}",
            access.repo_id, operation_id, snapshot.refs_sha256, snapshot.journal_sequence
        );
        let meta = TransferMeta { base: snapshot.manifest.clone(), final_refs: None, sidecars: None };
        faults::hit(
            &state.storage.root,
            "copy-before-transfer",
            sjson!({"repository_id": access.repo_id, "operation_id": operation_id,
                    "refs_sha256": snapshot.refs_sha256, "journal_sequence": snapshot.journal_sequence}),
        );
        let transfer_envelope = envelope(
            authority_incarnation,
            &actor,
            access.repo_id,
            &input.target_node_id,
            route.route_epoch,
            route.fencing_token,
            generation,
            path.clone(),
        );
        let bundle = replication::staging_root(&state)?.join(format!("{operation_id}.bundle"));
        let receipt = send_transfer(&state, &target.endpoint, &transfer_envelope, &path, &meta, Some(&bundle)).await?;
        if receipt.operation_id != operation_id
            || receipt.refs_sha256 != snapshot.refs_sha256
            || receipt.state != "verified"
        {
            return Err(conflict("target snapshot verification receipt mismatch"));
        }
        let _ = replication::clean_staging(&bundle);
        faults::hit(
            &state.storage.root,
            "copy-after-transfer",
            sjson!({"repository_id": access.repo_id, "operation_id": operation_id,
                    "refs_sha256": receipt.refs_sha256}),
        );
        base = Some(snapshot);
    }
    let base = base.ok_or_else(|| conflict("source snapshot manifest is missing"))?;
    let (state_name, digest, _sequence) = operation_state(&state, access.repo_id, operation_id).await?;
    op_state = state_name;
    if op_state != "verified" {
        return Err(conflict("target snapshot was not durably verified"));
    }
    if input.replicate_only {
        return Ok(json(
            StatusCode::OK,
            MigrationReceipt {
                operation_id,
                repository_id: access.repo_id,
                source_node_id: route.primary_node_id.clone(),
                target_node_id: input.target_node_id.clone(),
                refs_sha256: digest.or_else(|| Some(base.refs_sha256.clone())).unwrap_or_default(),
                old_route_epoch: route.route_epoch,
                new_route_epoch: route.route_epoch,
                state: "verified",
            },
        ));
    }

    // Phase 2: briefly drain admitted writers, capture the exact final manifest,
    // then build only the object delta while the source stays fenced.
    let cutover = locks::exclusive(&state, access.repo_id).await?;
    cutover.ensure_active()?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    auth::verify_token(&tx, &actor, true).await?;
    require_operator(&tx, &actor).await?;
    let current_incarnation: Uuid = tx
        .query_one("SELECT incarnation FROM cluster_authority WHERE singleton=true", &[])
        .await
        .map_err(Error::internal)?
        .get(0);
    if current_incarnation != authority_incarnation {
        return Err(conflict("metadata authority changed during transfer"));
    }
    let locked_generation: i64 = tx
        .query_one("SELECT storage_generation FROM repositories WHERE id=$1 FOR UPDATE", &[&access.repo_id])
        .await
        .map_err(Error::internal)?
        .get(0);
    let route = RepoShardRoute::row(&tx.query_one(&route_sql, &[&access.repo_id]).await.map_err(Error::internal)?);
    if route.primary_node_id != transport::node_id()?.unwrap_or_default()
        || route.route_epoch != base.source_route_epoch
        || locked_generation != generation
        || base.source_generation != generation
    {
        return Err(conflict("source placement changed during replication"));
    }
    if !route.draining {
        tx.execute(
            "UPDATE repository_shard_routes SET draining=true, fenced_epoch=GREATEST(fenced_epoch,$3), \
             version=version+1, updated_at=clock_timestamp() WHERE repository_id=$1 AND route_epoch=$2",
            &[&access.repo_id, &route.route_epoch, &route.route_epoch],
        )
        .await
        .map_err(Error::internal)?;
    } else if route.fenced_epoch < route.route_epoch {
        return Err(conflict("repository drain does not fence the previous epoch"));
    }
    crate::storage::ref_admission::fence_epoch(
        &tx,
        access.repo_id,
        route.route_epoch,
        crate::storage::ref_admission::DRAIN_WINDOW,
    )
    .await?;
    finish(tx, &actor, true).await?;
    let _ = crate::storage::ref_admission::cleanup_fenced(&state, access.repo_id).await;
    if !crate::journal::pending(&state.storage.root, access.repo_id).map_err(Error::internal)?.is_empty() {
        return Err(conflict("source has pending Git journal operations; reconcile before cutover"));
    }
    let final_manifest = replication::read_manifest_lease(&state, &repo, &cutover.lease).await?;
    let final_digest = final_manifest.digest();
    let final_sequence = crate::journal::sequence(&state.storage.root, access.repo_id).map_err(Error::internal)?;
    let sidecars = sidecar::capture(
        &state,
        access.repo_id,
        operation_id,
        access.owner_id,
        &object_format,
        generation,
        final_sequence,
        &final_manifest,
    )?;
    sidecar::write_progress(&state, &sidecars)?;
    let delta =
        replication::create_delta_bundle(&state, access.repo_id, operation_id, &base.manifest, &final_manifest).await?;
    drop(cutover);

    let path = format!(
        "/internal/shards/{}/delta/{}?base_refs_sha256={}&refs_sha256={}&journal_sequence={}",
        access.repo_id, operation_id, base.refs_sha256, final_digest, final_sequence
    );
    faults::hit(
        &state.storage.root,
        "final-delta-before-transfer",
        sjson!({"repository_id": access.repo_id, "operation_id": operation_id,
                "refs_sha256": final_digest, "journal_sequence": final_sequence,
                "sidecar_files": sidecars.files.len()}),
    );
    let meta = TransferMeta {
        base: base.manifest.clone(),
        final_refs: Some(final_manifest.clone()),
        sidecars: Some(sidecars.clone()),
    };
    let transfer_envelope = envelope(
        authority_incarnation,
        &actor,
        access.repo_id,
        &input.target_node_id,
        route.route_epoch,
        route.fencing_token,
        generation,
        path.clone(),
    );
    let receipt = send_transfer(&state, &target.endpoint, &transfer_envelope, &path, &meta, delta.as_deref()).await?;
    if receipt.operation_id != operation_id || receipt.refs_sha256 != final_digest || receipt.state != "verified" {
        return Err(conflict("target delta verification receipt mismatch"));
    }
    if let Some(delta) = delta {
        let _ = replication::clean_staging(&delta);
    }

    // Phase 3: re-acquire the source barrier and cut over only if the target
    // verified the exact manifest measured under the drain.
    let cutover = locks::exclusive(&state, access.repo_id).await?;
    cutover.ensure_active()?;
    let source_manifest = replication::read_manifest_lease(&state, &repo, &cutover.lease).await?;
    if source_manifest != final_manifest || source_manifest.digest() != receipt.refs_sha256 {
        return Err(conflict("source refs advanced after the verified delta"));
    }
    if crate::journal::sequence(&state.storage.root, access.repo_id).map_err(Error::internal)? != final_sequence {
        return Err(conflict("source journal advanced after migration drain"));
    }
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    auth::verify_token(&tx, &actor, true).await?;
    require_operator(&tx, &actor).await?;
    let current_incarnation: Uuid = tx
        .query_one("SELECT incarnation FROM cluster_authority WHERE singleton=true", &[])
        .await
        .map_err(Error::internal)?
        .get(0);
    if current_incarnation != authority_incarnation {
        return Err(conflict("metadata authority changed during transfer"));
    }
    let confirmed = tx
        .query_opt(
            "SELECT refs_sha256,journal_sequence,source_generation,source_route_epoch \
             FROM shard_replication_operations WHERE id=$1 AND repository_id=$2 AND state='verified' FOR UPDATE",
            &[&operation_id, &access.repo_id],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(|| conflict("replica verification state missing"))?;
    let confirmed_digest: String = confirmed.get(0);
    let confirmed_sequence: i64 = confirmed.get(1);
    let confirmed_generation: i64 = confirmed.get(2);
    let confirmed_epoch: i64 = confirmed.get(3);
    if confirmed_digest != receipt.refs_sha256
        || confirmed_sequence != final_sequence
        || confirmed_generation != generation
        || confirmed_epoch != route.route_epoch
    {
        return Err(conflict("replica verification state changed before cutover"));
    }
    let route = RepoShardRoute::row(&tx.query_one(&route_sql, &[&access.repo_id]).await.map_err(Error::internal)?);
    if route.primary_node_id != transport::node_id()?.unwrap_or_default()
        || route.route_epoch != confirmed_epoch
        || route.fencing_token != transfer_envelope.fencing_token
        || !route.draining
    {
        return Err(conflict("source placement changed during replication"));
    }
    crate::storage::ref_admission::fence_epoch(
        &tx,
        access.repo_id,
        route.route_epoch,
        crate::storage::ref_admission::DRAIN_WINDOW,
    )
    .await?;
    let settled_max: i64 = tx
        .query_one("SELECT COALESCE(MAX(sequence),0) FROM git_operations WHERE repository_id=$1", &[&access.repo_id])
        .await
        .map_err(Error::internal)?
        .get(0);
    if settled_max > final_sequence {
        return Err(conflict("source settled a Git operation after the verified snapshot"));
    }
    cutover.ensure_active()?;
    let new_epoch = route.route_epoch + 1;
    let new_token = route.fencing_token.max(new_epoch) + 1;
    let new_generation = generation + 1;
    faults::hit(
        &state.storage.root,
        "cutover-before-commit",
        sjson!({"repository_id": access.repo_id, "operation_id": operation_id,
                "new_route_epoch": new_epoch, "new_generation": new_generation}),
    );
    auth::authorize_repo_with_role(&tx, &actor, &owner, &name, Role::Admin).await?;
    let updated = tx
        .execute(
            "UPDATE repositories SET storage_generation=$2 WHERE id=$1 AND storage_generation=$3",
            &[&access.repo_id, &new_generation, &generation],
        )
        .await
        .map_err(Error::internal)?;
    if updated != 1 {
        return Err(conflict("repository generation changed during transfer"));
    }
    tx.execute(
        "UPDATE shard_nodes SET role='primary', lease_epoch=GREATEST(lease_epoch,$2), version=version+1 \
         WHERE node_id=$1",
        &[&input.target_node_id, &new_epoch],
    )
    .await
    .map_err(Error::internal)?;
    let upd = format!(
        "UPDATE repository_shard_routes SET primary_node_id=$2, route_epoch=$3, fencing_token=$4, \
         fenced_epoch=$5, required_generation=$6, required_op_sequence=GREATEST(required_op_sequence,$7), \
         draining=false, explicit_override=true, read_replica_nodes='[]'::jsonb, \
         replica_watermarks='{{}}'::jsonb, version=version+1, updated_at=clock_timestamp() \
         WHERE repository_id=$1 RETURNING {REPO_ROUTE_FIELDS}"
    );
    let moved = RepoShardRoute::row(
        &tx.query_one(
            &upd,
            &[
                &access.repo_id,
                &input.target_node_id,
                &new_epoch,
                &new_token,
                &route.route_epoch,
                &new_generation,
                &final_sequence,
            ],
        )
        .await
        .map_err(Error::internal)?,
    );
    tx.execute(
        "UPDATE shard_replication_operations SET state='completed', updated_at=clock_timestamp() \
         WHERE id=$1 AND state='verified'",
        &[&operation_id],
    )
    .await
    .map_err(Error::internal)?;
    let mut marker =
        VolumeFenceMarker::from_route(&moved, new_generation, Some(route.primary_node_id.clone()), unix_now());
    marker.primary_node_id = route.primary_node_id.clone();
    marker.read_only_degraded = true;
    record_audit_event(
        &tx,
        access.owner_id,
        access.repo_id,
        &actor,
        "shard.migrated",
        "shard_replication",
        &input.target_node_id,
        sjson!({
            "operation_id": operation_id,
            "refs_sha256": receipt.refs_sha256,
            "source": route.primary_node_id,
            "target": input.target_node_id,
            "online_initial_copy": true,
            "delta_applied": base.refs_sha256 != receipt.refs_sha256,
        }),
    )
    .await?;
    let transition_id = transitions::stage(&tx, &state, &marker).await?;
    cutover.ensure_active()?;
    transitions::commit_and_publish(&state, tx, &actor, &marker, transition_id).await?;
    faults::hit(
        &state.storage.root,
        "cutover-before-sidecar-finalize",
        sjson!({"repository_id": access.repo_id, "operation_id": operation_id}),
    );
    let finalize_path = format!("/internal/shards/{}/sidecar/{}", access.repo_id, operation_id);
    let finalize_envelope = envelope(
        authority_incarnation,
        &actor,
        access.repo_id,
        &input.target_node_id,
        new_epoch,
        moved.fencing_token,
        new_generation,
        finalize_path.clone(),
    );
    send_sidecar_finalize(&state, &target.endpoint, &finalize_envelope, &finalize_path, operation_id).await?;
    let _ = replication::clean_staging(&replication::base_path(&state, operation_id)?);
    Ok(json(
        StatusCode::OK,
        MigrationReceipt {
            operation_id,
            repository_id: access.repo_id,
            source_node_id: route.primary_node_id,
            target_node_id: input.target_node_id,
            refs_sha256: receipt.refs_sha256,
            old_route_epoch: route.route_epoch,
            new_route_epoch: new_epoch,
            state: "completed",
        },
    ))
}

pub async fn abort_migration(
    State(state): State<Arc<AppState>>,
    Path((owner, name)): Path<(String, String)>,
    headers: HeaderMap,
    Json(input): Json<AbortInput>,
) -> Result<Response, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = auth::authorize_repo_with_role(&tx, &actor, &owner, &name, Role::Admin).await?;
    require_operator(&tx, &actor).await?;
    let route = load_or_init_repo_route(&tx, access.owner_id, access.repo_id).await?;
    finish(tx, &actor, false).await?;
    if transport::node_id()?.as_deref() != Some(route.primary_node_id.as_str()) {
        return Err(conflict("migration abort must run on the source storage node"));
    }
    let _migration = locks::migration(&state, access.repo_id).await?;
    let mutation = locks::exclusive(&state, access.repo_id).await?;
    mutation.ensure_active()?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    auth::verify_token(&tx, &actor, true).await?;
    require_operator(&tx, &actor).await?;
    let generation: i64 = tx
        .query_one("SELECT storage_generation FROM repositories WHERE id=$1 FOR UPDATE", &[&access.repo_id])
        .await
        .map_err(Error::internal)?
        .get(0);
    let route_sql =
        format!("SELECT {REPO_ROUTE_FIELDS} FROM repository_shard_routes WHERE repository_id=$1 FOR UPDATE");
    let route = RepoShardRoute::row(&tx.query_one(&route_sql, &[&access.repo_id]).await.map_err(Error::internal)?);
    if input.expected_route_epoch.is_some_and(|epoch| epoch != route.route_epoch) {
        return Err(conflict("migration abort route epoch mismatch"));
    }
    let op = tx
        .query_opt(
            "SELECT source_node_id,state,source_route_epoch FROM shard_replication_operations \
             WHERE id=$1 AND repository_id=$2 FOR UPDATE",
            &[&input.operation_id, &access.repo_id],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    let source: String = op.get(0);
    let op_state: String = op.get(1);
    let op_epoch: i64 = op.get(2);
    if source != route.primary_node_id {
        return Err(conflict("migration abort source mismatch"));
    }
    if op_state == "aborted" {
        finish(tx, &actor, false).await?;
        return Ok(json(
            StatusCode::OK,
            sjson!({
                "operation_id": input.operation_id,
                "repository_id": access.repo_id,
                "state": "aborted",
            }),
        ));
    }
    if op_state == "completed" {
        return Err(conflict("migration operation is already terminal"));
    }
    if route.draining && op_epoch != route.route_epoch {
        return Err(conflict("migration operation epoch differs from the drained route"));
    }
    if route.draining {
        let new_epoch = route.route_epoch + 1;
        let new_token = route.fencing_token.max(new_epoch) + 1;
        let upd = format!(
            "UPDATE repository_shard_routes SET route_epoch=$2, fencing_token=$3, fenced_epoch=$4, \
             required_generation=$5, draining=false, read_only_degraded=false, degraded_reason='', \
             version=version+1, updated_at=clock_timestamp() WHERE repository_id=$1 \
             RETURNING {REPO_ROUTE_FIELDS}"
        );
        let updated = RepoShardRoute::row(
            &tx.query_one(&upd, &[&access.repo_id, &new_epoch, &new_token, &route.route_epoch, &generation])
                .await
                .map_err(Error::internal)?,
        );
        crate::storage::ref_admission::fence_epoch(&tx, access.repo_id, route.route_epoch, std::time::Duration::ZERO)
            .await?;
        let marker = VolumeFenceMarker::from_route(&updated, generation, None, unix_now());
        tx.execute(
            "UPDATE shard_replication_operations SET state='aborted', updated_at=clock_timestamp() WHERE id=$1",
            &[&input.operation_id],
        )
        .await
        .map_err(Error::internal)?;
        record_audit_event(
            &tx,
            access.owner_id,
            access.repo_id,
            &actor,
            "shard.migration_aborted",
            "shard_replication",
            &route.primary_node_id,
            sjson!({"operation_id": input.operation_id, "released_drain": true, "route_epoch": new_epoch}),
        )
        .await?;
        let transition_id = transitions::stage(&tx, &state, &marker).await?;
        mutation.ensure_active()?;
        transitions::commit_and_publish(&state, tx, &actor, &marker, transition_id).await?;
        let _ = replication::clean_staging(&replication::base_path(&state, input.operation_id)?);
        return Ok(json(
            StatusCode::OK,
            sjson!({
                "operation_id": input.operation_id,
                "repository_id": access.repo_id,
                "state": "aborted",
                "route_epoch": new_epoch,
            }),
        ));
    }
    tx.execute(
        "UPDATE shard_replication_operations SET state='aborted', updated_at=clock_timestamp() WHERE id=$1",
        &[&input.operation_id],
    )
    .await
    .map_err(Error::internal)?;
    record_audit_event(
        &tx,
        access.owner_id,
        access.repo_id,
        &actor,
        "shard.migration_aborted",
        "shard_replication",
        &route.primary_node_id,
        sjson!({"operation_id": input.operation_id, "released_drain": false}),
    )
    .await?;
    finish(tx, &actor, true).await?;
    let _ = replication::clean_staging(&replication::base_path(&state, input.operation_id)?);
    Ok(json(
        StatusCode::OK,
        sjson!({
            "operation_id": input.operation_id,
            "repository_id": access.repo_id,
            "state": "aborted",
            "route_epoch": route.route_epoch,
        }),
    ))
}

/// List durable migration operations so an operator can resume a
/// server-generated operation id or abort a drained transfer after a crash.
/// Listing never resumes or promotes on its own.
pub async fn list_migrations(
    State(state): State<Arc<AppState>>,
    Path((owner, name)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = auth::authorize_repo_with_role(&tx, &actor, &owner, &name, Role::Read).await?;
    require_operator(&tx, &actor).await?;
    let rows = tx
        .query(
            "SELECT id,target_node_id,state,source_route_epoch,source_generation, \
             refs_sha256,journal_sequence,created_at::text,updated_at::text \
             FROM shard_replication_operations WHERE repository_id=$1 \
             ORDER BY created_at DESC, id DESC LIMIT 100",
            &[&access.repo_id],
        )
        .await
        .map_err(Error::internal)?;
    let items: Vec<serde_json::Value> = rows
        .iter()
        .map(|row| {
            let state_name: String = row.get(2);
            sjson!({
                "operation_id": row.get::<_, Uuid>(0),
                "target_node_id": row.get::<_, String>(1),
                "state": state_name,
                "source_route_epoch": row.get::<_, i64>(3),
                "source_generation": row.get::<_, i64>(4),
                "refs_sha256": row.get::<_, Option<String>>(5),
                "journal_sequence": row.get::<_, Option<i64>>(6),
                "created_at": row.get::<_, String>(7),
                "updated_at": row.get::<_, String>(8),
                "resumable": matches!(state_name.as_str(), "copying" | "verified"),
            })
        })
        .collect();
    finish(tx, &actor, false).await?;
    Ok(json(StatusCode::OK, sjson!({"items": items})))
}
