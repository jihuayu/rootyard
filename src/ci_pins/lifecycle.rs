//! CI pin lifecycle implementation.
use super::*;
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct ReleaseRequest {
    job_id: Option<Uuid>,
    target_oid: Option<String>,
    storage_generation: Option<i64>,
}

pub async fn list_pins(
    State(state): State<Arc<AppState>>,
    Path((owner, name)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    tokio::spawn(async move { list_pins_inner(state, owner, name, None, headers).await })
        .await
        .map_err(Error::internal)?
}

pub async fn get_pin(
    State(state): State<Arc<AppState>>,
    Path((owner, name, job)): Path<(String, String, Uuid)>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    tokio::spawn(async move { list_pins_inner(state, owner, name, Some(job), headers).await })
        .await
        .map_err(Error::internal)?
}

pub(super) async fn list_pins_inner(
    state: Arc<AppState>,
    owner: String,
    name: String,
    single_job: Option<Uuid>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    if owner != actor.username || !db::valid_name(&owner) || !db::valid_name(&name) {
        return Err(Error::not_found());
    }
    let row = state
        .pool
        .get()
        .await
        .map_err(Error::internal)?
        .query_opt(
            &format!("{} WHERE r.owner_id=$1 AND r.name=$2", db::REPO_SELECT),
            &[&actor.id, &name],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    let repo = db::Repository::from_row(&row);
    if repo.state != "ready" {
        return Err(Error(
            StatusCode::SERVICE_UNAVAILABLE,
            "repository not ready",
        ));
    }
    let _slot = state.git_slots.clone().try_acquire_owned().map_err(|_| {
        Error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Git capacity exhausted; retry later",
        )
    })?;
    let _lock = tokio::time::timeout(state.config.git_timeout, state.storage.write_lock(repo.id))
        .await
        .map_err(|_| Error::timeout())?;
    let existing = intents(&state.storage.root, repo.id).map_err(Error::internal)?;
    let native = roots(&state, repo.id).await.map_err(Error::internal)?;
    let active_jobs = crate::ci_checkouts::active_job_ids(&state.pool, repo.id)
        .await
        .map_err(Error::internal)?;
    let dir = directory(&state.storage.root, repo.id);
    let mut records: Vec<Intent> = existing.into_values().collect();
    records.sort_by(|a, b| {
        (a.storage_generation, a.job_id.to_string())
            .cmp(&(b.storage_generation, b.job_id.to_string()))
    });
    let mut items = Vec::with_capacity(records.len());
    for intent in records {
        if single_job.is_some_and(|job| job != intent.job_id) {
            continue;
        }
        let has_receipt = journal::exists(&dir.join(format!("{}.pinned.json", intent.job_id)))
            .map_err(Error::internal)?;
        let has_native = native.get(&intent.retention_ref) == Some(&intent.target_oid);
        let pin_state = if has_receipt && has_native {
            "pinned"
        } else {
            "intent"
        };
        let mut value = serde_json::to_value(&intent).map_err(Error::internal)?;
        value["state"] = pin_state.into();
        value["active_checkout_lease"] = active_jobs.contains(&intent.job_id).into();
        items.push(value);
    }
    if single_job.is_some() {
        let item = items.into_iter().next().ok_or_else(Error::not_found)?;
        return Ok(([(header::CACHE_CONTROL, "no-store")], Json(item)).into_response());
    }
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(items)).into_response())
}

pub async fn release_pin(
    State(state): State<Arc<AppState>>,
    Path((owner, name, job)): Path<(String, String, Uuid)>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response, Error> {
    tokio::spawn(async move { release_pin_inner(state, owner, name, job, headers, body).await })
        .await
        .map_err(Error::internal)?
}

pub(super) async fn release_pin_inner(
    state: Arc<AppState>,
    owner: String,
    name: String,
    job: Uuid,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response, Error> {
    let req = if body.is_empty() {
        ReleaseRequest::default()
    } else {
        serde_json::from_slice::<ReleaseRequest>(&body).map_err(|_| Error::bad_request())?
    };
    if req.job_id.is_some_and(|id| id != job)
        || req
            .target_oid
            .as_ref()
            .is_some_and(|oid| !nonzero_oid(oid))
        || req.storage_generation.is_some_and(|g| g <= 0)
    {
        return Err(Error::bad_request());
    }
    let actor = auth::authenticate(&state.pool, &headers).await?;
    auth::writable(&actor)?;
    if owner != actor.username || !db::valid_name(&owner) || !db::valid_name(&name) {
        return Err(Error::not_found());
    }
    let row = state
        .pool
        .get()
        .await
        .map_err(Error::internal)?
        .query_opt(
            &format!("{} WHERE r.owner_id=$1 AND r.name=$2", db::REPO_SELECT),
            &[&actor.id, &name],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    let repo = db::Repository::from_row(&row);
    if req
        .storage_generation
        .is_some_and(|g| g != repo.storage_generation)
    {
        return Err(Error(StatusCode::CONFLICT, "repository generation changed"));
    }
    if repo.state != "ready" {
        return Err(Error(
            StatusCode::SERVICE_UNAVAILABLE,
            "repository not ready",
        ));
    }
    let _slot = state.git_slots.clone().try_acquire_owned().map_err(|_| {
        Error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Git capacity exhausted; retry later",
        )
    })?;
    let _lock = tokio::time::timeout(state.config.git_timeout, state.storage.write_lock(repo.id))
        .await
        .map_err(|_| Error::timeout())?;
    let _admission = crate::storage::admission::acquire(
        &state.pool,
        repo.id,
        repo.storage_generation,
        "ci-pin-release",
        tokio::time::Instant::now() + state.config.git_timeout,
    )
    .await?;
    reliability::before_gitfs_push(&state, &repo).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    tx.batch_execute("SET LOCAL lock_timeout='5s'; SET LOCAL statement_timeout='10s'")
        .await
        .map_err(Error::internal)?;
    tx.query_opt(
        "SELECT t.id FROM tokens t JOIN users u ON u.id=t.user_id \
         WHERE t.id=$1 AND t.user_id=$2 AND u.username=$3 FOR SHARE OF t,u",
        &[&actor.token_id, &actor.id, &owner],
    )
    .await
    .map_err(Error::internal)?
    .ok_or_else(Error::unauthorized)?;
    let locked = tx
        .query_opt(
            "SELECT state,storage_generation FROM repositories \
             WHERE id=$1 AND owner_id=$2 AND name=$3 FOR SHARE",
            &[&repo.id, &actor.id, &name],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    let token = tx
        .query_opt(
            "SELECT read_only FROM tokens \
             WHERE id=$1 AND user_id=$2 AND digest=$3 AND NOT revoked \
               AND (expires_at IS NULL OR expires_at > clock_timestamp())",
            &[&actor.token_id, &actor.id, &actor.token_digest],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::unauthorized)?;
    if token.get::<_, bool>(0) {
        return Err(Error(StatusCode::FORBIDDEN, "write permission required"));
    }
    if locked.get::<_, i64>(1) != repo.storage_generation {
        return Err(Error(StatusCode::CONFLICT, "repository generation changed"));
    }
    if locked.get::<_, String>(0) != "ready" {
        return Err(Error(
            StatusCode::SERVICE_UNAVAILABLE,
            "repository not ready",
        ));
    }
    tx.execute(
        "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
        &[&format!("ci-checkout:{}:{}", repo.id, job)],
    )
    .await
    .map_err(Error::internal)?;
    // F14: crate::ci_checkouts::has_active_lease_on(&tx, repo.id, job)
    if crate::ci_checkouts::has_active_lease_on(&*tx, repo.id, job)
        .await
        .map_err(Error::internal)?
    {
        return Err(Error(
            StatusCode::CONFLICT,
            "active checkout lease exists for job",
        ));
    }
    let retention_ref = format!("{NAMESPACE}/jobs/{job}");
    let existing = intents(&state.storage.root, repo.id).map_err(Error::internal)?;
    let native = roots(&state, repo.id)
        .await
        .map_err(|_| Error(StatusCode::CONFLICT, "CI retention namespace collision"))?;
    if let Some(intent) = existing.get(&retention_ref).cloned() {
        if intent.owner_id != actor.id {
            return Err(Error::not_found());
        }
        if req
            .target_oid
            .as_ref()
            .is_some_and(|oid| oid != &intent.target_oid)
            || req
                .storage_generation
                .is_some_and(|g| g != intent.storage_generation)
        {
            return Err(Error(
                StatusCode::CONFLICT,
                "pin target or generation mismatch",
            ));
        }
        if let Some(actual_oid) = native.get(&retention_ref) {
            if actual_oid != &intent.target_oid {
                return Err(Error(
                    StatusCode::CONFLICT,
                    "unmanaged or changed CI retention ref; operator investigation required",
                ));
            }
        }
        // Step 1: Remove <job>.pinned.json first so <job>.pinned.json never outlives <job>.json.
        let dir = directory(&state.storage.root, repo.id);
        let pinned_file = dir.join(format!("{job}.pinned.json"));
        if journal::exists(&pinned_file).map_err(Error::internal)? {
            std::fs::remove_file(&pinned_file).map_err(Error::internal)?;
            std::fs::File::open(&dir)
                .and_then(|f| f.sync_all())
                .map_err(Error::internal)?;
        }
        // Step 2: Delete native ref refs/rootyard-ci/jobs/{job} and publish observed_immutable_ci_root event.
        if native.contains_key(&retention_ref) {
            let operation = journal::begin(
                &state.storage.root,
                repo.id,
                actor.id,
                actor.username.clone(),
                actor.token_id,
                repo.storage_generation,
            )
            .map_err(Error::internal)?;
            let mut cmd = git(&state, repo.id).map_err(Error::internal)?;
            cmd.args([
                "-c",
                "core.hooksPath=/dev/null",
                "update-ref",
                "-d",
                "--no-deref",
                &intent.retention_ref,
                &intent.target_oid,
            ]);
            let result = git_http::collect_git_output(cmd, 4096, state.config.git_timeout).await;
            journal::finish(&operation).map_err(Error::internal)?;
            result.map_err(Error::internal)?;
            let updated_native = roots(&state, repo.id).await.map_err(Error::internal)?;
            if updated_native.contains_key(&intent.retention_ref) {
                return Err(Error::internal("CI retention root deletion not verified"));
            }
            tx.commit().await.map_err(Error::internal)?;
            drop(client);
            let changes = vec![crate::events::RefEventInput {
                transaction_sequence: 1,
                ref_name: intent.retention_ref.clone(),
                old_oid: intent.target_oid.clone(),
                new_oid: zero_oid(&intent.target_oid),
            }];
            let evidence = serde_json::json!({
                "version": 1,
                "kind": "observed_immutable_ci_root",
                "action": "released",
                "intent": intent,
                "finished": true,
                "interrupted": false,
                "retained": false
            });
            crate::events::publish(
                &state.pool,
                &crate::events::OperationRecord {
                    id: operation.id,
                    repository_id: repo.id,
                    actor_id: operation.actor_id,
                    token_id: operation.token_id,
                    service_principal_id: operation.service_principal_id,
                    actor_name: operation.actor_name.clone(),
                    sequence: operation.sequence,
                    storage_generation: operation.storage_generation,
                    outcome: "recorded".into(),
                    evidence,
                    admission: None,
                },
                &changes,
            )
            .await
            .map_err(Error::internal)?;
            state.dispatch.committed();
            journal::retire(&operation).map_err(Error::internal)?;
        } else {
            tx.commit().await.map_err(Error::internal)?;
            drop(client);
        }
        // Step 3: Remove <job>.json to free MAX_PINS slot.
        let intent_file = dir.join(format!("{job}.json"));
        if journal::exists(&intent_file).map_err(Error::internal)? {
            std::fs::remove_file(&intent_file).map_err(Error::internal)?;
            std::fs::File::open(&dir)
                .and_then(|f| f.sync_all())
                .map_err(Error::internal)?;
        }
        let mut value = serde_json::to_value(&intent).map_err(Error::internal)?;
        value["state"] = "released".into();
        value["released"] = true.into();
        return Ok(([(header::CACHE_CONTROL, "no-store")], Json(value)).into_response());
    }
    if native.contains_key(&retention_ref) {
        return Err(Error(
            StatusCode::CONFLICT,
            "unmanaged or changed CI retention ref; operator investigation required",
        ));
    }
    let prior = tx
        .query_opt(
            "SELECT evidence->'intent' FROM git_operations \
             WHERE repository_id = $1 \
               AND outcome = 'recorded' \
               AND evidence->>'kind' = 'observed_immutable_ci_root' \
               AND evidence->'intent'->>'job_id' = $2 \
             ORDER BY sequence DESC LIMIT 1",
            &[&repo.id, &job.to_string()],
        )
        .await
        .map_err(Error::internal)?;
    tx.commit().await.map_err(Error::internal)?;
    drop(client);
    if let Some(row) = prior {
        let mut value: serde_json::Value = row.get(0);
        value["state"] = "released".into();
        value["released"] = true.into();
        return Ok(([(header::CACHE_CONTROL, "no-store")], Json(value)).into_response());
    }
    Err(Error::not_found())
}

