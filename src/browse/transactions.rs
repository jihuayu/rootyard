//! Atomic multi-ref compare-and-swap (CAS) transactions (`POST /ref-transactions`).
use crate::{
    AppState, Error, auth,
    browse::{
        git_read,
        models::{AppliedRefUpdate, RefTransactionRequest, RefTransactionResponse},
    },
    db, events, journal, reliability, storage,
};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use deadpool_postgres::Transaction;
use serde_json::Value;
use std::{
    collections::HashMap,
    fs::OpenOptions,
    io::{Seek, SeekFrom, Write},
    os::unix::fs::OpenOptionsExt,
    process::Stdio,
    sync::Arc,
};
use uuid::Uuid;

async fn creation_replay(
    tx: &Transaction<'_>,
    actor: Uuid,
    repo: Uuid,
    key: &str,
    request: &Value,
) -> Result<Option<Value>, Error> {
    let inserted = tx
        .execute(
            "INSERT INTO forge_creation_requests (tenant_id,repository_id,idempotency_key,request) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING",
            &[&actor, &repo, &key, &request],
        )
        .await
        .map_err(Error::internal)?;
    if inserted == 1 {
        return Ok(None);
    }
    let row = tx
        .query_one(
            "SELECT request,response FROM forge_creation_requests WHERE tenant_id=$1 AND repository_id=$2 AND idempotency_key=$3",
            &[&actor, &repo, &key],
        )
        .await
        .map_err(Error::internal)?;
    if row.get::<_, Value>("request") != *request {
        return Err(Error(StatusCode::CONFLICT, "idempotency key conflict"));
    }
    row.get::<_, Option<Value>>("response")
        .map(Some)
        .ok_or_else(|| Error::internal("incomplete creation record"))
}

async fn record_creation(
    tx: &Transaction<'_>,
    actor: Uuid,
    repo: Uuid,
    key: Option<&str>,
    response: &Value,
) -> Result<(), Error> {
    if let Some(key) = key {
        let changed = tx
            .execute(
                "UPDATE forge_creation_requests SET response=$4 WHERE tenant_id=$1 AND repository_id=$2 AND idempotency_key=$3 AND response IS NULL",
                &[&actor, &repo, &key, &response],
            )
            .await
            .map_err(Error::internal)?;
        if changed != 1 {
            return Err(Error::internal("creation record was not finalized"));
        }
    }
    Ok(())
}

pub fn build_update_ref_stdin_payload(updates: &[AppliedRefUpdate]) -> Vec<u8> {
    let mut sorted = updates.to_vec();
    sorted.sort_by(|a, b| a.ref_name.cmp(&b.ref_name));
    let mut buf = Vec::with_capacity(64 + sorted.len() * 128);
    buf.extend_from_slice(b"start\0");
    for u in &sorted {
        buf.extend_from_slice(b"update ");
        buf.extend_from_slice(u.ref_name.as_bytes());
        buf.push(0);
        buf.extend_from_slice(u.new_oid.as_bytes());
        buf.push(0);
        buf.extend_from_slice(u.old_oid.as_bytes());
        buf.push(0);
    }
    buf.extend_from_slice(b"prepare\0commit\0");
    buf
}

pub async fn execute_ref_transaction(
    State(state): State<Arc<AppState>>,
    Path((owner, name)): Path<(String, String)>,
    headers: HeaderMap,
    Json(input): Json<RefTransactionRequest>,
) -> Result<Response, Error> {
    tokio::spawn(async move { execute_ref_transaction_inner(state, owner, name, headers, input, None).await })
        .await
        .map_err(Error::internal)?
}

/// The only in-process bypass for proposal retention refs is an absent-to-commit pin.
/// No HTTP route exposes this operation; normal ref transactions reject the prefix.
pub(crate) async fn create_proposal_pin(
    state: Arc<AppState>,
    owner: String,
    name: String,
    headers: HeaderMap,
    proposal_id: Uuid,
    target_oid: String,
    storage_generation: i64,
) -> Result<Response, Error> {
    let request = RefTransactionRequest {
        storage_generation: Some(storage_generation),
        atomic: true,
        updates: vec![crate::browse::models::RefUpdateInput {
            ref_name: crate::namespace_service::proposal_pin_ref(proposal_id),
            old_oid: None,
            new_oid: Some(target_oid),
        }],
    };
    tokio::spawn(async move {
        execute_ref_transaction_inner(state, owner, name, headers, request, Some(proposal_id)).await
    })
    .await
    .map_err(Error::internal)?
}

async fn execute_ref_transaction_inner(
    state: Arc<AppState>,
    owner: String,
    name: String,
    headers: HeaderMap,
    input: RefTransactionRequest,
    proposal_pin: Option<Uuid>,
) -> Result<Response, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    auth::writable(&actor)?;
    let idem_key = auth::idempotency_key(&headers)?.map(str::to_owned);
    let normalized_updates = input.normalize_with_proposal_pin(proposal_pin)?;

    if !db::valid_name(&owner) || !db::valid_name(&name) {
        return Err(Error::not_found());
    }
    let repo_row = state
        .pool
        .get()
        .await
        .map_err(Error::internal)?
        .query_opt(
            &format!("{} WHERE ns.slug=$1 AND r.name=$2", db::REPO_SELECT),
            &[&owner, &name],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    let mut repo = db::Repository::from_row(&repo_row);

    let _slot = state.git_slots.clone().try_acquire_owned().map_err(|_| {
        Error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Git capacity exhausted; retry later",
        )
    })?;
    let ref_names = normalized_updates.iter().map(|update| update.ref_name.clone())
        .collect::<Vec<_>>();
    let publication = storage::ref_publication::acquire(&state.pool,repo.id,
        repo.storage_generation,&ref_names,
        tokio::time::Instant::now()+state.config.git_timeout).await?;
    let _write_guard = publication.enter_window(&state.storage,
        tokio::time::Instant::now()+state.config.git_timeout).await?;

    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let repo_id = auth::authorize_repo(&tx, &actor, &owner, &name, true).await?;
    let current_generation: i64 = tx
        .query_one(
            "SELECT storage_generation FROM repositories WHERE id=$1 FOR SHARE",
            &[&repo_id],
        )
        .await
        .map_err(Error::internal)?
        .get(0);

    let request_json = serde_json::json!({
        "operation": "ref_transaction",
        "storage_generation": input.storage_generation,
        "atomic": input.atomic,
        "updates": normalized_updates,
    });
    if let Some(ref key) = idem_key {
        if let Some(saved_response) =
            creation_replay(&tx, actor.id, repo_id, key, &request_json).await?
        {
            auth::finish_tx(tx, &actor, true).await?;
            return Ok((
                StatusCode::OK,
                [(header::CACHE_CONTROL, "no-store")],
                Json(saved_response),
            )
                .into_response());
        }
    }

    if let Some(expected_gen) = input.storage_generation {
        if expected_gen != current_generation {
            return Err(Error(StatusCode::CONFLICT, "storage generation mismatch"));
        }
    }
    repo.storage_generation = current_generation;
    reliability::before_push(&state, &repo)
        .await
        .map_err(Error::internal)?;

    let repo_path = state.storage.verify_path(repo_id).map_err(Error::internal)?;
    let quota = state.config.max_repo_bytes;
    let check_path = repo_path.clone();
    let used_bytes = tokio::task::spawn_blocking(move || storage::disk_bytes(&check_path, quota))
        .await
        .map_err(Error::internal)?
        .map_err(Error::internal)?;
    if used_bytes.saturating_add(4096) > quota {
        return Err(Error(
            StatusCode::INSUFFICIENT_STORAGE,
            "repository quota reached",
        ));
    }

    let repo_format = crate::browse::object_format::detect_repo_object_format(&state, repo_id).await?;
    let zero_oid = repo_format.zero_oid();
    let (head, current_refs) = git_read::read_head_and_refs(&state, repo_id).await?;
    let refs_map: HashMap<&str, &str> = current_refs
        .iter()
        .map(|r| (r.name.as_str(), r.oid.as_str()))
        .collect();

    for u in &normalized_updates {
        if !crate::browse::object_format::valid_oid_for_format(&u.old_oid, repo_format)
            || !crate::browse::object_format::valid_oid_for_format(&u.new_oid, repo_format)
        {
            return Err(Error(
                StatusCode::CONFLICT,
                "ref transaction object format does not match repository",
            ));
        }
        let actual_old = refs_map.get(u.ref_name.as_str()).copied().unwrap_or(zero_oid);
        if actual_old != u.old_oid {
            return Err(Error(StatusCode::CONFLICT, "reference old_oid mismatch"));
        }
        if u.new_oid == zero_oid {
            if head.target.as_deref() == Some(u.ref_name.as_str()) {
                return Err(Error(
                    StatusCode::CONFLICT,
                    "cannot delete current HEAD branch",
                ));
            }
        } else {
            let kind = git_read::object_type(&state, repo_id, &u.new_oid).await?;
            let Some(kind_str) = kind else {
                return Err(Error(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "target object does not exist",
                ));
            };
            if u.ref_name.starts_with("refs/heads/") && kind_str != "commit" {
                return Err(Error(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "branch reference target must be a commit",
                ));
            }
        }
    }

    let requested: Vec<journal::RefChange> = normalized_updates.iter().map(|u| journal::RefChange {
        ref_name: u.ref_name.clone(), old_oid: u.old_oid.clone(), new_oid: u.new_oid.clone(),
    }).collect();
    crate::browse::policy::validate(&*tx, repo_id, &requested, &state.config.git, &repo_path, state.config.git_timeout).await?;
    let owner_id: Uuid = tx.query_one("SELECT owner_id FROM repositories WHERE id=$1", &[&repo_id])
        .await.map_err(Error::internal)?.get(0);
    Box::pin(crate::lfs::publication::validate_new_refs(&state, &tx, repo_id, owner_id, &requested)).await?;
    Box::pin(crate::lfs::locks::validate_new_refs_with_client(&*tx, &repo_path,
        &state.config.git, state.config.git_timeout, repo_id, actor.id, &requested)).await?;

    auth::verify_token(&tx, &actor, true).await?;

    let journal_root = state.storage.root.join("journal");
    journal::mkdir(&journal_root).map_err(Error::internal)?;
    let stdin_path = journal_root.join(format!(".tmp-stdin-{}", Uuid::new_v4()));
    let mut stdin_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&stdin_path)
        .map_err(Error::internal)?;
    let _ = std::fs::remove_file(&stdin_path);
    let stdin_payload = build_update_ref_stdin_payload(&normalized_updates);
    stdin_file
        .write_all(&stdin_payload)
        .map_err(Error::internal)?;
    stdin_file
        .seek(SeekFrom::Start(0))
        .map_err(Error::internal)?;

    let operation = journal::begin(
        &state.storage.root,
        repo_id,
        actor.id,
        actor.username.clone(),
        actor.token_id,
        current_generation,
    )
    .map_err(Error::internal)?;
    journal::record_ref_transaction_intent(&operation, &requested).map_err(Error::internal)?;

    let mut cmd = git_read::git_cmd(&state, repo_id)?;
    cmd.args(["update-ref", "--stdin", "-z", "--no-deref"]);
    if let Err(err) = crate::git_http::collect_git_output_input(
        cmd,
        4096,
        state.config.git_timeout,
        Stdio::from(stdin_file),
    )
    .await
    {
        // Git can report a definite CAS conflict or commit all refs and lose
        // its acknowledgement. Observe the refs after the child is reaped,
        // while the repository lock still excludes another writer.
        let mut all_old = true;
        let mut all_new = true;
        for change in &requested {
            let observed = match git_read::run_git(&state, repo_id,
                &["show-ref", "--verify", "--hash", &change.ref_name], 128).await {
                Ok(raw) => Some(String::from_utf8_lossy(&raw).trim().to_owned()),
                Err(e) if e.0 == StatusCode::NOT_FOUND => Some(zero_oid.to_owned()),
                Err(_) => None,
            };
            all_old &= observed.as_deref() == Some(change.old_oid.as_str());
            all_new &= observed.as_deref() == Some(change.new_oid.as_str());
        }
        if all_old {
            journal::finish(&operation).map_err(Error::internal)?;
            tx.rollback().await.map_err(Error::internal)?;
            reliability::complete(&state, Some(operation)).await.map_err(Error::internal)?;
            return Err(Error(StatusCode::CONFLICT, "reference transaction conflict"));
        }
        if !all_new {
            journal::mark_interrupted(&operation).map_err(Error::internal)?;
            journal::finish(&operation).map_err(Error::internal)?;
            tx.rollback().await.map_err(Error::internal)?;
            let _ = reliability::reconcile(&state, repo_id, current_generation, false).await;
            if err.to_string().contains("timed out") { return Err(Error::timeout()); }
            return Err(Error(StatusCode::SERVICE_UNAVAILABLE, "reference transaction outcome requires recovery"));
        }
    }
    journal::record_ref_transaction_receipt(&operation, &requested).map_err(Error::internal)?;
    journal::finish(&operation).map_err(Error::internal)?;

    let event_inputs: Vec<events::RefEventInput> = normalized_updates
        .iter()
        .enumerate()
        .map(|(i, u)| events::RefEventInput {
            transaction_sequence: (i + 1) as i64,
            ref_name: u.ref_name.clone(),
            old_oid: u.old_oid.clone(),
            new_oid: u.new_oid.clone(),
        })
        .collect();
    let changes_json: Vec<Value> = normalized_updates
        .iter()
        .map(|u| {
            serde_json::json!({
                "ref_name": u.ref_name,
                "old_oid": u.old_oid,
                "new_oid": u.new_oid,
            })
        })
        .collect();
    let evidence = serde_json::json!({
        "version": 1,
        "kind": "ref_transaction",
        "finished": true,
        "interrupted": false,
        "storage_generation_matches": true,
        "reference_events": [{
            "ordinal": 1,
            "phase": "Committed",
            "changes": changes_json,
        }],
        "post_receive": changes_json,
    });

    events::publish(
        &state.pool,
        &events::OperationRecord {
            id: operation.id,
            repository_id: repo_id,
            actor_id: actor.id,
            token_id: actor.token_id,
            service_principal_id: None,
            actor_name: actor.username.clone(),
            sequence: operation.sequence,
            storage_generation: current_generation,
            outcome: "recorded".into(),
            evidence,
        },
        &event_inputs,
    )
    .await
    .map_err(Error::internal)?;
    state.dispatch.committed();
    journal::retire(&operation).map_err(Error::internal)?;

    let response_body = RefTransactionResponse {
        operation_id: operation.id,
        repository_id: repo_id,
        storage_generation: current_generation,
        sequence: operation.sequence,
        atomic: true,
        updates: normalized_updates,
    };
    let response_value = serde_json::to_value(&response_body).map_err(Error::internal)?;
    record_creation(&tx, actor.id, repo_id, idem_key.as_deref(), &response_value).await?;
    tx.commit().await.map_err(Error::internal)?;

    Ok((
        StatusCode::OK,
        [(header::CACHE_CONTROL, "no-store")],
        Json(response_value),
    )
        .into_response())
}
