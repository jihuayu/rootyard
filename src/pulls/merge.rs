//! Same-generation atomic Pull Request merge handler coordinating PostgreSQL row locks,
//! per-repository storage write locks, native Git CAS `update-ref --no-deref`, and outbox events.
use crate::{
    AppState, Error,
    auth::{self, finish_tx as finish, idempotency_key},
    db, events, git_http, journal,
    pulls::{
        models::{
            MergeInput, PULL_FIELDS, PullRequest, body_valid, creation_replay, git_cmd, json,
            positive, record_creation, resolve_ref_oid, valid_oid, valid_oid_for_format,
        },
        rules,
    },
    reliability, storage,
};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use std::sync::Arc;
use tokio::time::Instant;

pub async fn merge_pull(
    State(state): State<Arc<AppState>>,
    Path((owner, name, number)): Path<(String, String, i64)>,
    headers: HeaderMap,
    Json(input): Json<MergeInput>,
) -> Result<Response, Error> {
    let web_scope = auth::web_scope_enabled();
    tokio::spawn(auth::inherit_web_scope(web_scope, async move {
        merge_pull_inner(state, owner, name, number, headers, input).await
    }))
    .await
    .map_err(Error::internal)?
}

async fn merge_pull_inner(
    state: Arc<AppState>,
    owner: String,
    name: String,
    number: i64,
    headers: HeaderMap,
    input: MergeInput,
) -> Result<Response, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    positive(number)?;
    positive(input.expected_version)?;
    let strategy_str = input.strategy.as_deref().unwrap_or("fast_forward");
    if !valid_oid(&input.expected_head_oid)
        || !valid_oid(&input.expected_base_oid)
        || input.storage_generation.is_some_and(|g| g <= 0)
        || !matches!(strategy_str, "fast_forward" | "merge_commit")
        || input
            .commit_message
            .as_ref()
            .is_some_and(|m| !body_valid(m, true))
    {
        return Err(Error::bad_request());
    }
    let key = idempotency_key(&headers)?.map(str::to_owned);

    let (repo_id, tenant_id) = {
        let mut client = state.pool.get().await.map_err(Error::internal)?;
        let tx = client.transaction().await.map_err(Error::internal)?;
        let access =
            auth::authorize_repo_with_role(&tx, &actor, &owner, &name, auth::Role::Write, crate::token_scopes::RepoAction::PullsWrite).await?;
        finish(tx, &actor, true).await?;
        (access.repo_id, access.owner_id)
    };
    let repo_row = state
        .pool
        .get()
        .await
        .map_err(Error::internal)?
        .query_opt(&format!("{} WHERE r.id=$1", db::REPO_SELECT), &[&repo_id])
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    let repo = db::Repository::from_row(&repo_row);
    if repo.state != "ready" {
        return Err(Error(StatusCode::CONFLICT, "repository is not ready"));
    }
    if let Some(expected_gen) = input.storage_generation
        && repo.storage_generation != expected_gen {
            return Err(Error(
                StatusCode::CONFLICT,
                "repository storage generation mismatch",
            ));
        }
    if !valid_oid_for_format(&input.expected_head_oid, &repo.object_format)
        || !valid_oid_for_format(&input.expected_base_oid, &repo.object_format)
    {
        return Err(Error::bad_request());
    }

    // The immutable PR base ref chooses the exact publication key before any
    // local mutex. Its row and candidate are checked again under the window.
    let base_ref: String = state.pool.get().await.map_err(Error::internal)?
        .query_opt("SELECT base_ref FROM forge_pulls WHERE repository_id=$1 AND number=$2",
            &[&repo.id,&number]).await.map_err(Error::internal)?
        .ok_or_else(Error::not_found)?.get(0);
    let publication = storage::ref_publication::acquire(&state.pool,repo.id,
        repo.storage_generation,&[base_ref],Instant::now()+state.config.git_timeout).await?;

    let _slot = state.git_slots.clone().try_acquire_owned().map_err(|_| {
        Error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Git capacity exhausted; retry later",
        )
    })?;
    let _write_guard = publication.enter_window(&state.storage,
        Instant::now()+state.config.git_timeout).await?;
    let _admission = storage::admission::acquire(
        &state.pool,
        repo.id,
        repo.storage_generation,
        "pull-merge",
        Instant::now() + state.config.git_timeout,
    )
    .await?;
    reliability::before_gitfs_push(&state, &repo).await?;
    publication.ensure_active()?;

    let repo_path = state
        .storage
        .verify_path(repo.id)
        .map_err(Error::internal)?;
    let quota = state.config.max_repo_bytes;
    let size = tokio::task::spawn_blocking({
        let p = repo_path.clone();
        move || storage::disk_bytes(&p, quota)
    })
    .await
    .map_err(Error::internal)?
    .map_err(Error::internal)?;
    if size.saturating_add(4096) >= quota {
        return Err(Error(
            StatusCode::INSUFFICIENT_STORAGE,
            "repository quota reached",
        ));
    }

    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let repo_id = auth::authorize_repo_with_role(&tx, &actor, &owner, &name, auth::Role::Write, crate::token_scopes::RepoAction::PullsWrite).await?.repo_id;

    let current_gen: i64 = tx
        .query_one(
            "SELECT storage_generation FROM repositories WHERE id=$1",
            &[&repo_id],
        )
        .await
        .map_err(Error::internal)?
        .get(0);
    if current_gen != repo.storage_generation {
        return Err(Error(
            StatusCode::CONFLICT,
            "repository storage generation changed",
        ));
    }

    if let Some(ref k) = key {
        let canonical_request = serde_json::json!({
            "operation": "pull_merge",
            "pull_number": number,
            "expected_version": input.expected_version,
            "expected_head_oid": input.expected_head_oid,
            "expected_base_oid": input.expected_base_oid,
            "storage_generation": input.storage_generation,
            "strategy": strategy_str,
            "commit_message": input.commit_message,
        });
        if let Some(saved) = creation_replay(&tx, tenant_id, repo_id, k, &canonical_request).await?
        {
            finish(tx, &actor, true).await?;
            return Ok(json(StatusCode::OK, saved));
        }
    }

    let pull_row = tx
        .query_opt(
            &format!(
                "SELECT {PULL_FIELDS} FROM forge_pulls WHERE tenant_id=$1 AND repository_id=$2 AND number=$3 FOR UPDATE"
            ),
            &[&tenant_id, &repo_id, &number],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    let pull = PullRequest::row(&pull_row);

    if pull.state != "open" {
        return Err(Error(StatusCode::CONFLICT, "pull request is not open"));
    }
    if pull.version != input.expected_version {
        return Err(Error(StatusCode::CONFLICT, "pull request version conflict"));
    }
    if pull.head_oid != input.expected_head_oid {
        return Err(Error(
            StatusCode::CONFLICT,
            "pull request head_oid mismatch",
        ));
    }
    if pull.base_oid != input.expected_base_oid {
        return Err(Error(
            StatusCode::CONFLICT,
            "pull request base_oid mismatch",
        ));
    }

    let policy = rules::evaluate_branch_policy(
        &tx,
        tenant_id,
        repo_id,
        number,
        &pull.base_ref,
        &input.expected_head_oid,
    )
    .await?;
    if !policy.allowed {
        return Err(Error(
            StatusCode::CONFLICT,
            policy
                .reason
                .unwrap_or("branch protection policy not satisfied"),
        ));
    }
    if strategy_str == "merge_commit" && policy.require_fast_forward {
        return Err(Error(
            StatusCode::CONFLICT,
            "branch protection rule requires fast-forward merge",
        ));
    }

    let live_head = resolve_ref_oid(&state, repo_id, &pull.head_ref)
        .await?
        .ok_or(Error(
            StatusCode::CONFLICT,
            "live head branch ref does not exist",
        ))?;
    if !valid_oid_for_format(&live_head, &repo.object_format) {
        return Err(Error::internal("live head OID differs from repository object format"));
    }
    if live_head != input.expected_head_oid {
        return Err(Error(
            StatusCode::CONFLICT,
            "live head ref moved from expected_head_oid",
        ));
    }
    let live_base = resolve_ref_oid(&state, repo_id, &pull.base_ref)
        .await?
        .ok_or(Error(
            StatusCode::CONFLICT,
            "live base branch ref does not exist",
        ))?;
    if !valid_oid_for_format(&live_base, &repo.object_format) {
        return Err(Error::internal("live base OID differs from repository object format"));
    }
    if live_base != input.expected_base_oid {
        return Err(Error(
            StatusCode::CONFLICT,
            "live base ref moved from expected_base_oid",
        ));
    }

    let merged_oid = if strategy_str == "fast_forward" {
        let mut ff_cmd = git_cmd(&state, repo_id)?;
        ff_cmd.args([
            "merge-base",
            "--is-ancestor",
            &input.expected_base_oid,
            &input.expected_head_oid,
        ]);
        if git_http::collect_git_output(ff_cmd, 256, state.config.git_timeout)
            .await
            .is_err()
        {
            return Err(Error(
                StatusCode::CONFLICT,
                "fast-forward not possible; head is not a descendant of base",
            ));
        }
        input.expected_head_oid.clone()
    } else {
        let mut tree_cmd = git_cmd(&state, repo_id)?;
        tree_cmd.args([
            "merge-tree",
            "--write-tree",
            &input.expected_base_oid,
            &input.expected_head_oid,
        ]);
        let tree_out = git_http::collect_git_output(tree_cmd, 64 * 1024, state.config.git_timeout)
            .await
            .map_err(|_| Error(StatusCode::CONFLICT, "merge conflict detected"))?;
        let tree_str = std::str::from_utf8(&tree_out).map_err(Error::internal)?;
        let tree_oid = tree_str.lines().next().unwrap_or("").trim();
        if !valid_oid_for_format(tree_oid, &repo.object_format) {
            return Err(Error::internal("invalid tree oid from git merge-tree"));
        }
        let default_msg = format!("Merge pull request #{} from {}", number, pull.head_ref);
        let msg = input.commit_message.as_deref().unwrap_or(&default_msg);
        let mut commit_cmd = git_cmd(&state, repo_id)?;
        commit_cmd
            .env("GIT_AUTHOR_NAME", &actor.username)
            .env(
                "GIT_AUTHOR_EMAIL",
                format!("{}@rootyard.local", actor.username),
            )
            .env("GIT_COMMITTER_NAME", &actor.username)
            .env(
                "GIT_COMMITTER_EMAIL",
                format!("{}@rootyard.local", actor.username),
            )
            .args([
                "commit-tree",
                tree_oid,
                "-p",
                &input.expected_base_oid,
                "-p",
                &input.expected_head_oid,
                "-m",
                msg,
            ]);
        let commit_out = git_http::collect_git_output(commit_cmd, 1024, state.config.git_timeout)
            .await
            .map_err(Error::internal)?;
        let commit_oid = std::str::from_utf8(&commit_out)
            .map_err(Error::internal)?
            .trim()
            .to_owned();
        if !valid_oid_for_format(&commit_oid, &repo.object_format) {
            return Err(Error::internal("invalid commit oid from git commit-tree"));
        }
        commit_oid
    };

    let ref_change = journal::RefChange {
        ref_name: pull.base_ref.clone(),
        old_oid: input.expected_base_oid.clone(),
        new_oid: merged_oid.clone(),
    };
    Box::pin(crate::lfs::publication::validate_new_refs(
        &state,
        &tx,
        repo_id,
        tenant_id,
        std::slice::from_ref(&ref_change),
    ))
    .await?;
    Box::pin(crate::lfs::locks::validate_new_refs_with_client(
        &*tx,
        &repo_path,
        &state.config.git,
        state.config.git_timeout,
        repo_id,
        actor.id,
        &[ref_change],
    ))
    .await?;

    auth::verify_token(&tx, &actor, true).await?;
    publication.ensure_active()?;

    let op = journal::begin(
        &state.storage.root,
        repo_id,
        actor.id,
        actor.username.clone(),
        actor.token_id,
        repo.storage_generation,
    )
    .map_err(Error::internal)?;

    let mut update_cmd = state.storage.git(&state.config);
    update_cmd
        .arg("-c")
        .arg("core.hooksPath=/dev/null")
        .arg("--no-replace-objects")
        .arg("--git-dir")
        .arg(&repo_path)
        .args([
            "update-ref",
            "--no-deref",
            &pull.base_ref,
            &merged_oid,
            &input.expected_base_oid,
        ]);
    if git_http::collect_git_output(update_cmd, 4096, state.config.git_timeout)
        .await
        .is_err()
    {
        drop(tx);
        drop(client);
        let _ = journal::finish(&op);
        let no_op_evidence = serde_json::json!({
            "version": 1,
            "kind": "pull_merge",
            "pull_number": number,
            "finished": true,
            "interrupted": false,
            "reference_events": [],
            "post_receive": [],
            "storage_generation_matches": true,
        });
        let _ = events::publish(
            &state.pool,
            &events::OperationRecord {
                id: op.id,
                repository_id: repo_id,
                actor_id: actor.id,
                token_id: actor.token_id,
                service_principal_id: None,
                actor_name: actor.username.clone(),
                sequence: op.sequence,
                storage_generation: repo.storage_generation,
                outcome: "no_ref_changes".into(),
                evidence: no_op_evidence,
                admission: None,
            },
            &[],
        )
        .await;
        let _ = journal::retire(&op);
        return Err(Error(StatusCode::CONFLICT, "atomic ref update rejected"));
    }
    journal::finish(&op).map_err(Error::internal)?;
    publication.ensure_active()?;

    let updated_row = tx
        .query_opt(
            &format!(
                "UPDATE forge_pulls \
                 SET state='merged', \
                     merge_commit_oid=$5, \
                     merged_storage_generation=$6, \
                     version=version+1, \
                     updated_at=clock_timestamp() \
                 WHERE tenant_id=$1 AND repository_id=$2 AND number=$3 AND version=$4 AND state='open' \
                 RETURNING {PULL_FIELDS}"
            ),
            &[
                &tenant_id,
                &repo_id,
                &number,
                &input.expected_version,
                &merged_oid,
                &repo.storage_generation,
            ],
        )
        .await
        .map_err(Error::internal)?
        .ok_or(Error(
            StatusCode::CONFLICT,
            "pull request merge state conflict",
        ))?;
    let merged_pull = PullRequest::row(&updated_row);
    let response_val = serde_json::to_value(&merged_pull).map_err(Error::internal)?;
    record_creation(&tx, tenant_id, repo_id, key.as_deref(), &response_val).await?;
    finish(tx, &actor, true).await?;
    drop(client);

    let evidence = serde_json::json!({
        "version": 1,
        "kind": "pull_merge",
        "pull_number": number,
        "strategy": strategy_str,
        "finished": true,
        "interrupted": false,
        "reference_events": [],
        "post_receive": [{
            "ref_name": merged_pull.base_ref,
            "old_oid": input.expected_base_oid,
            "new_oid": merged_oid,
        }],
        "storage_generation_matches": true,
    });
    let changes = vec![events::RefEventInput {
        transaction_sequence: 1,
        ref_name: merged_pull.base_ref.clone(),
        old_oid: input.expected_base_oid.clone(),
        new_oid: merged_oid.clone(),
    }];
    events::publish(
        &state.pool,
        &events::OperationRecord {
            id: op.id,
            repository_id: repo_id,
            actor_id: actor.id,
            token_id: actor.token_id,
            service_principal_id: None,
            actor_name: actor.username.clone(),
            sequence: op.sequence,
            storage_generation: repo.storage_generation,
            outcome: "recorded".into(),
            evidence,
            admission: None,
        },
        &changes,
    )
    .await
    .map_err(Error::internal)?;
    state.dispatch.committed();
    journal::retire(&op).map_err(Error::internal)?;
    Ok(json(StatusCode::OK, response_val))
}
