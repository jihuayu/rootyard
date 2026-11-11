//! Atomic multi-ref compare-and-swap (CAS) transactions (`POST /ref-transactions`).
use crate::{
    AppState, Error, auth,
    browse::{
        git_read, idempotency,
        ref_transaction::{RefTransactionRequest, RefTransactionResponse, build_update_ref_stdin_payload},
    },
    db::{self, Identity}, events, journal,
    members::models::RepoAccess, reliability, storage,
};
use axum::{
    Json,
    extract::{Extension, Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use std::{
    collections::HashMap,
    fs::OpenOptions,
    io::{Seek, SeekFrom, Write},
    os::unix::fs::OpenOptionsExt,
    process::Stdio,
    sync::Arc,
};
use uuid::Uuid;

pub async fn execute_ref_transaction(
    State(state): State<Arc<AppState>>,
    Path((owner, name)): Path<(String, String)>,
    Extension(actor): Extension<Identity>,
    headers: HeaderMap,
    Json(input): Json<RefTransactionRequest>,
) -> Result<Response, Error> {
    tokio::spawn(async move { execute_ref_transaction_inner(state, owner, name, actor, headers, input, None).await })
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
        updates: vec![crate::browse::ref_transaction::RefUpdateInput {
            ref_name: crate::namespace_service::proposal_pin_ref(proposal_id),
            old_oid: None,
            new_oid: Some(target_oid),
        }],
    };
    let actor = auth::authenticate(&state.pool, &headers).await?;
    tokio::spawn(async move {
        execute_ref_transaction_inner(state, owner, name, actor, headers, request, Some(proposal_id)).await
    })
    .await
    .map_err(Error::internal)?
}

async fn execute_ref_transaction_inner(
    state: Arc<AppState>,
    owner: String,
    name: String,
    actor: Identity,
    headers: HeaderMap,
    input: RefTransactionRequest,
    proposal_pin: Option<Uuid>,
) -> Result<Response, Error> {
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
    let repo = db::Repository::from_row(&repo_row);
    crate::pando_gateway::transition::admit_write(&state.pool, repo.id, &repo.storage_backend).await?;

    // Fail an unauthorized caller before acquiring durable publication and
    // admission rows or reserving journal state. The transaction-scoped
    // authorize below still binds token locks to the long settlement; this
    // preflight only closes the side-effect window for a read-only or
    // unaffiliated caller.
    {
        let client = state.pool.get().await.map_err(Error::internal)?;
        auth::verify_repo_write_access(
            &**client,
            actor.id,
            actor.token_id,
            repo.id,
            auth::web_scope_enabled(),
            crate::token_scopes::RepoAction::ContentsWrite,
        )
        .await?;
    }

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
    // The durable admission precedes this writer's native ref update. A
    // committed physical-GC fence rejects the write instead of racing it.
    let _admission = storage::admission::acquire(
        &state.pool,
        repo.id,
        repo.storage_generation,
        "ref-transaction",
        tokio::time::Instant::now() + state.config.git_timeout,
    )
    .await?;
    // Reconcile before opening the settlement transaction: reconciliation may
    // update `repositories` under its own lock, and doing that here avoids
    // waiting on this request's `FOR SHARE` row lock.
    if repo.state != "ready" {
        return Err(Error(StatusCode::CONFLICT, "repository is not ready"));
    }
    if let Some(expected_gen) = input.storage_generation
        && expected_gen != repo.storage_generation {
            return Err(Error(StatusCode::CONFLICT, "storage generation mismatch"));
        }
    reliability::before_gitfs_push(&state, &repo).await?;

    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = auth::authorize_repo_with_role(&tx, &actor, &owner, &name, auth::Role::Write, crate::token_scopes::RepoAction::ContentsWrite).await?;
    let RepoAccess { repo_id, owner_id: tenant_id, .. } = access;
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
        // A crash after native publication rolls back the claim row with the
        // settlement transaction. The journal fingerprint proves the recorded
        // operation already belongs to this exact key/request pair, so replay
        // it instead of running a second CAS against the published refs.
        let saved = match idempotency::replay_terminal(&tx, tenant_id, repo_id, key, &request_json).await? {
            Some(saved) => Some(saved),
            None => idempotency::claim(&tx, tenant_id, repo_id, key, &request_json).await?,
        };
        if let Some(saved_response) = saved {
            auth::finish_tx(tx, &actor, true).await?;
            return Ok((
                StatusCode::OK,
                [(header::CACHE_CONTROL, "no-store")],
                Json(saved_response),
            )
                .into_response());
        }
    }

    if let Some(expected_gen) = input.storage_generation
        && expected_gen != current_generation {
            return Err(Error(StatusCode::CONFLICT, "storage generation mismatch"));
        }
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
    Box::pin(crate::lfs::publication::validate_new_refs(&state, &tx, repo_id, tenant_id, &requested)).await?;
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

    let idempotency = idem_key.as_deref().map(|key| {
        let (key_sha256, request_sha256) = idempotency::fingerprint(key, &request_json);
        journal::IdempotencyIntent { key_sha256, request_sha256 }
    });
    let operation = if let Some(proposal_id)=proposal_pin {
        let intent=crate::namespace_service::ProposalIntent{
            proposal_id,repository_id:repo_id,target_oid:requested[0].new_oid.clone(),
        };
        journal::begin_proposal(&state.storage.root,repo_id,actor.id,
            actor.username.clone(),actor.token_id,current_generation,intent,idempotency)
    } else {
        journal::begin_ref_transaction(&state.storage.root,repo_id,actor.id,
            actor.username.clone(),actor.token_id,current_generation,idempotency)
    }.map_err(Error::internal)?;

    // Any setup failure after the durable intent exists but before the native
    // CAS is provably ref-free: finish and retire the journal, then roll the
    // claim back so a retry cannot wedge on this request's own lock.
    let pre_cas = async {
        journal::record_ref_transaction_intent(&operation, &requested).map_err(Error::internal)?;
        // Test-only rendezvous for revoking a token while this request is still
        // before native publication. It is an inert no-op unless explicitly set.
        if let Some(millis) = test_pause_before_cas() {
            tokio::time::sleep(std::time::Duration::from_millis(millis)).await;
        }
        // Re-check the caller's token and effective role BEFORE the native CAS.
        // A revoked writer must abort the intent while refs are still untouched.
        auth::verify_repo_write_access(&*tx, actor.id, actor.token_id, repo_id,
            auth::web_scope_enabled(), crate::token_scopes::RepoAction::ContentsWrite).await?;
        if test_failpoint("before_cas") {
            return Err(Error(StatusCode::SERVICE_UNAVAILABLE, "reference transaction aborted before CAS"));
        }
        git_read::git_cmd(&state, repo_id)
    }.await;
    let mut cmd = match pre_cas {
        Ok(cmd) => cmd,
        Err(error) => {
            let _ = journal::finish(&operation);
            let rollback = tx.rollback().await.map_err(Error::internal);
            journal::retire(&operation).map_err(Error::internal)?;
            rollback?;
            return Err(error);
        }
    };
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
            // `show-ref --verify` reports a missing ref as the generic fatal
            // 128, which can also mean a damaged repository. The quiet
            // `rev-parse --verify` probe answers exactly 1 for "this ref does
            // not exist", which is the observation a create needs: a missing
            // old ref is the zero id, not a broken read.
            let observed = match git_read::run_git(&state, repo_id, git_read::GitStep::RefVerify,
                &["rev-parse", "--verify", "--quiet", &change.ref_name], 128).await {
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
    if let Err(error) = journal::record_ref_transaction_receipt(&operation, &requested)
        .and_then(|()| journal::finish(&operation))
        .map_err(Error::internal)
    {
        // The intent is now provably post-CAS; never retire it unsettled.
        let _ = tx.rollback().await;
        let _ = reliability::reconcile(&state, repo_id, current_generation, false).await;
        return Err(error);
    }
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
    // Read back the journal records that reconciliation will see instead of
    // re-deriving a second shape. Live settlement and startup recovery now
    // produce byte-identical evidence for the same committed operation.
    let reference_events = journal::events(&operation).map_err(Error::internal)?;
    let requested_evidence = journal::requests(&operation).map_err(Error::internal)?;
    let receipt_evidence = journal::receipts(&operation).map_err(Error::internal)?;
    let evidence = journal::ref_transaction_evidence(
        &operation,
        current_generation,
        true,
        false,
        &reference_events,
        requested_evidence.as_deref(),
        receipt_evidence.as_deref(),
    );

    let response_body = RefTransactionResponse {
        operation_id: operation.id,
        repository_id: repo_id,
        storage_generation: current_generation,
        sequence: operation.sequence,
        atomic: true,
        updates: normalized_updates,
    };
    let response_value = serde_json::to_value(&response_body).map_err(Error::internal)?;

    if test_failpoint("after_receipt") {
        tx.rollback().await.map_err(Error::internal)?;
        return Err(Error(StatusCode::SERVICE_UNAVAILABLE, "reference transaction settlement interrupted"));
    }

    // Operation + exact outbox set + Idempotency-Key response are one
    // PostgreSQL transaction. Native Git already published the refs, but no
    // durable SQL settlement exists until this commit succeeds.
    if let Err(error) = events::publish_in_tx(
        &tx,
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
            admission: None,
        },
        &event_inputs,
    )
    .await
    {
        let _ = tx.rollback().await;
        let _ = reliability::reconcile(&state, repo_id, current_generation, false).await;
        return Err(Error::internal(error));
    }
    // Test-only crash point after the outbox set has been inserted but before
    // the claim finalization/commit. Rolling the caller-owned transaction back
    // is exactly what a process death here does: neither the operation nor its
    // events are durable, while the Git receipt and journal remain.
    if test_failpoint("after_publish") {
        tx.rollback().await.map_err(Error::internal)?;
        return Err(Error(StatusCode::SERVICE_UNAVAILABLE, "reference transaction settlement interrupted"));
    }
    if let Err(error) =
        idempotency::record(&tx, tenant_id, repo_id, idem_key.as_deref(), &response_value).await
    {
        let _ = tx.rollback().await;
        let _ = reliability::reconcile(&state, repo_id, current_generation, false).await;
        return Err(error);
    }
    if let Err(error) = tx.commit().await {
        // Commit may have applied before the client observed an error. The
        // journal is authoritative either way; reconcile replays or settles it.
        let _ = reliability::reconcile(&state, repo_id, current_generation, false).await;
        return Err(Error::internal(error));
    }
    if test_failpoint("after_commit") {
        return Err(Error(StatusCode::SERVICE_UNAVAILABLE, "reference transaction retirement interrupted"));
    }
    state.dispatch.committed();
    // Retire only after the settlement commit. A crash here leaves a finished
    // journal beside an identical recorded operation; reconciliation retires it.
    journal::retire(&operation).map_err(Error::internal)?;

    Ok((
        StatusCode::OK,
        [(header::CACHE_CONTROL, "no-store")],
        Json(response_value),
    )
        .into_response())
}

/// Native-boundary rendezvous. Inert unless the process environment explicitly
/// sets `ROOTYARD_TEST_REF_TRANSACTION_PAUSE_BEFORE_CAS_MS`; production never does.
fn test_pause_before_cas() -> Option<u64> {
    let value = std::env::var("ROOTYARD_TEST_REF_TRANSACTION_PAUSE_BEFORE_CAS_MS").ok()?;
    value.parse().ok().map(|millis: u64| millis.min(10_000))
}

/// Native-boundary crash hook. Inert unless explicitly armed by a native
/// boundary test through `ROOTYARD_TEST_REF_TRANSACTION_FAILPOINT`, either as
/// this exact name or as `file:<path>` whose trimmed content names it.
fn test_failpoint(name: &str) -> bool {
    let Ok(value) = std::env::var("ROOTYARD_TEST_REF_TRANSACTION_FAILPOINT") else { return false };
    value == name || value.strip_prefix("file:").is_some_and(|path| {
        std::fs::read_to_string(path).is_ok_and(|contents| contents.trim() == name)
    })
}
