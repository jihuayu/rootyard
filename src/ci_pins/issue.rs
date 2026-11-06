//! CI pin issue implementation.
use super::*;
pub async fn pin(
    State(state): State<Arc<AppState>>,
    Path((owner, name)): Path<(String, String)>,
    headers: HeaderMap,
    Json(input): Json<PinRequest>,
) -> Result<Response, Error> {
    tokio::spawn(async move { pin_inner(state, owner, name, headers, input).await })
        .await
        .map_err(Error::internal)?
}
pub(super) async fn pin_inner(
    state: Arc<AppState>,
    owner: String,
    name: String,
    headers: HeaderMap,
    input: PinRequest,
) -> Result<Response, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    auth::writable(&actor)?;
    if owner != actor.username || !db::valid_name(&owner) || !db::valid_name(&name) {
        return Err(Error::not_found());
    }
    if !nonzero_oid(&input.target_oid) || input.storage_generation <= 0 {
        return Err(Error::bad_request());
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
    if !valid_format(&repo.object_format)
        || !nonzero_oid_for_format(&input.target_oid, &repo.object_format)
    {
        return Err(Error::bad_request());
    }
    if repo.storage_generation != input.storage_generation {
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
    reliability::before_push(&state, &repo)
        .await
        .map_err(Error::internal)?;
    // Hold current token/owner/repository authority through ref publication. The
    // durable journal is reconciled after releasing SQL locks; it is not rolled
    // back by a database disconnect and never pretends to be a SQL transaction.
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    tx.batch_execute("SET LOCAL lock_timeout='5s'; SET LOCAL statement_timeout='10s'")
        .await
        .map_err(Error::internal)?;
    tx.query_opt("SELECT t.id FROM tokens t JOIN users u ON u.id=t.user_id WHERE t.id=$1 AND t.user_id=$2 AND u.username=$3 FOR SHARE OF t,u", &[&actor.token_id,&actor.id,&owner]).await.map_err(Error::internal)?.ok_or_else(Error::unauthorized)?;
    let locked = tx.query_opt("SELECT state,storage_generation FROM repositories WHERE id=$1 AND owner_id=$2 AND name=$3 FOR SHARE", &[&repo.id,&actor.id,&name]).await.map_err(Error::internal)?.ok_or_else(Error::not_found)?;
    let token = tx.query_opt("SELECT read_only FROM tokens WHERE id=$1 AND user_id=$2 AND digest=$3 AND NOT revoked AND (expires_at IS NULL OR expires_at > clock_timestamp())", &[&actor.token_id,&actor.id,&actor.token_digest]).await.map_err(Error::internal)?.ok_or_else(Error::unauthorized)?;
    if token.get::<_, bool>(0) {
        return Err(Error(StatusCode::FORBIDDEN, "write permission required"));
    }
    if locked.get::<_, i64>(1) != input.storage_generation {
        return Err(Error(StatusCode::CONFLICT, "repository generation changed"));
    }
    if locked.get::<_, String>(0) != "ready" {
        return Err(Error(
            StatusCode::SERVICE_UNAVAILABLE,
            "repository not ready",
        ));
    }
    let intent = Intent {
        version: 1,
        job_id: input.job_id,
        owner_id: actor.id,
        repository_id: repo.id,
        storage_generation: input.storage_generation,
        object_format: repo.object_format.clone(),
        target_oid: input.target_oid,
        retention_ref: format!("{NAMESPACE}/jobs/{}", input.job_id),
    };
    let existing = intents(&state.storage.root, repo.id).map_err(Error::internal)?;
    if let Some(prior) = existing.get(&intent.retention_ref) {
        if prior != &intent {
            return Err(Error(
                StatusCode::CONFLICT,
                "job already has a different target or generation",
            ));
        }
    } else if existing.len() >= MAX_PINS {
        return Err(Error(
            StatusCode::TOO_MANY_REQUESTS,
            "CI plan admission limit reached",
        ));
    }
    let native = roots(&state, repo.id)
        .await
        .map_err(|_| Error(StatusCode::CONFLICT, "CI retention namespace collision"))?;
    for (name, oid) in &native {
        if !existing
            .get(name)
            .is_some_and(|plan| plan.target_oid == *oid && plan.owner_id == actor.id)
        {
            return Err(Error(
                StatusCode::CONFLICT,
                "unmanaged or changed CI retention ref; operator investigation required",
            ));
        }
    }
    commit(&state, repo.id, &intent.target_oid)
        .await
        .map_err(|_| Error(StatusCode::CONFLICT, "exact commit unavailable"))?;
    let repo_path = state
        .storage
        .verify_path(repo.id)
        .map_err(Error::internal)?;
    let quota = state.config.max_repo_bytes;
    let size = tokio::task::spawn_blocking(move || storage::disk_bytes(&repo_path, quota))
        .await
        .map_err(Error::internal)?
        .map_err(Error::internal)?;
    if size.saturating_add(4096) >= quota {
        return Err(Error(
            StatusCode::INSUFFICIENT_STORAGE,
            "repository quota reached",
        ));
    }
    let root = state.storage.root.join("ci-pins");
    journal::mkdir(&root).map_err(Error::internal)?;
    let dir = directory(&state.storage.root, repo.id);
    journal::mkdir(&dir).map_err(Error::internal)?;
    journal::atomic(
        &dir.join(format!("{}.json", intent.job_id)),
        &serde_json::to_vec(&intent).map_err(Error::internal)?,
        false,
    )
    .map_err(Error::internal)?;
    if !native.contains_key(&intent.retention_ref) {
        // A pinned receipt without its root is corruption, never permission to
        // recreate or overwrite a previously promised immutable retention root.
        if journal::exists(&dir.join(format!("{}.pinned.json", intent.job_id)))
            .map_err(Error::internal)?
        {
            return Err(Error::internal("pinned CI root missing"));
        }
        let operation =
            journal::begin_ci(&state.storage.root, actor.username, actor.token_id, &intent)
                .map_err(Error::internal)?;
        let mut cmd = git(&state, repo.id).map_err(Error::internal)?;
        cmd.arg("-c")
            .arg(format!(
                "core.hooksPath={}",
                state.storage.root.join("managed-hooks").display()
            ))
            .env("ROOTYARD_JOURNAL_OPERATION", &operation.path)
            .args([
                "update-ref",
                "--no-deref",
                &intent.retention_ref,
                &intent.target_oid,
                &zero_oid(&intent.target_oid),
            ]);
        // collect_git_output owns/kills/waits for the entire child process group.
        // A failed/timeout command is not evidence of rollback; reconcile refs.
        let result = git_http::collect_git_output(cmd, 4096, state.config.git_timeout).await;
        journal::finish(&operation).map_err(Error::internal)?;
        drop(tx);
        drop(client);
        reliability::complete(&state, Some(operation))
            .await
            .map_err(Error::internal)?;
        result.map_err(Error::internal)?;
    } else {
        tx.commit().await.map_err(Error::internal)?;
        drop(client);
    }
    let native = roots(&state, repo.id).await.map_err(Error::internal)?;
    if native.get(&intent.retention_ref) != Some(&intent.target_oid) {
        return Err(Error::internal("CI retention root not verified"));
    }
    receipt(&state.storage.root, &intent).map_err(Error::internal)?;
    // Revalidate before returning a usable receipt; a revoked caller may have
    // retained bytes but cannot obtain new readiness or read access.
    let current = auth::authenticate(&state.pool, &headers).await?;
    auth::writable(&current)?;
    if current.id != actor.id || current.username != owner {
        return Err(Error::unauthorized());
    }
    let current_repo = state
        .pool
        .get()
        .await
        .map_err(Error::internal)?
        .query_one(
            "SELECT state,storage_generation FROM repositories WHERE id=$1 AND owner_id=$2",
            &[&repo.id, &actor.id],
        )
        .await
        .map_err(Error::internal)?;
    if current_repo.get::<_, String>(0) != "ready"
        || current_repo.get::<_, i64>(1) != intent.storage_generation
    {
        return Err(Error(
            StatusCode::CONFLICT,
            "repository changed during pinning",
        ));
    }
    let mut value = serde_json::to_value(intent).map_err(Error::internal)?;
    value["state"] = "pinned".into();
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(value)).into_response())
}

/// Verify retained native truth under the caller-held repository writer lock.
/// The receipt is evidence of retention, never an authorization source.
pub(crate) async fn verify_receipt(state: &AppState, expected: &Intent) -> Result<String> {
    use sha2::{Digest, Sha256};
    expected.validate()?;
    ensure!(
        load_intent(&state.storage.root, expected.repository_id, expected.job_id)? == *expected,
        "source intent differs"
    );
    let bytes = journal::read(
        &directory(&state.storage.root, expected.repository_id)
            .join(format!("{}.pinned.json", expected.job_id)),
    )?;
    ensure!(
        bytes == serde_json::to_vec(expected)?,
        "source receipt differs"
    );
    let path = state.storage.verify_path(expected.repository_id)?;
    for forbidden in [
        "shallow",
        "info/grafts",
        "objects/info/alternates",
        "objects/info/http-alternates",
    ] {
        ensure!(
            !journal::exists(&path.join(forbidden))?,
            "unsupported source object topology"
        );
    }
    ensure!(
        roots(state, expected.repository_id)
            .await?
            .get(&expected.retention_ref)
            == Some(&expected.target_oid),
        "source retention missing or changed"
    );
    commit(state, expected.repository_id, &expected.target_oid).await?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

