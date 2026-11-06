//! HTTP handlers for Branch Protection Rules and merge policy evaluation.
use crate::{
    AppState, Error,
    auth::{self, authorize_repo as authorize, finish_tx as finish, idempotency_key},
    members::{audit, models::Role, rbac},
    pulls::models::{
        BranchRule, BranchRuleInput, Page, RULE_FIELDS, context_valid, creation_replay, json,
        normalize_branch_ref, record_creation, repo_tenant_id,
    },
};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use deadpool_postgres::Transaction;
use serde::Serialize;
use serde_json::Value;
use std::{collections::HashSet, sync::Arc};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize)]
pub struct PolicyEvaluation {
    pub allowed: bool,
    pub require_fast_forward: bool,
    pub required_approvals: i64,
    pub current_approvals: i64,
    pub required_checks: Vec<String>,
    pub missing_or_failed_checks: Vec<String>,
    pub reason: Option<&'static str>,
}

async fn policy_write_lock(state: &AppState, owner: &str, name: &str)
    -> Result<tokio::sync::OwnedMutexGuard<()>, Error> {
    let client = state.pool.get().await.map_err(Error::internal)?;
    let row = client.query_opt(
        "SELECT r.id FROM repositories r JOIN namespaces u ON u.id=r.owner_id WHERE u.slug=$1 AND r.name=$2",
        &[&owner,&name],
    ).await.map_err(Error::internal)?.ok_or_else(Error::not_found)?;
    let repo_id: Uuid = row.get(0);
    drop(client);
    tokio::time::timeout(state.config.git_timeout, state.storage.write_lock(repo_id))
        .await.map_err(|_| Error::timeout())
}

async fn has_self_approval_col(tx: &Transaction<'_>) -> Result<bool, Error> {
    let sql = "SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='forge_branch_rules' AND column_name='prevent_self_approval')";
    Ok(tx.query_one(sql, &[]).await.map_err(Error::internal)?.get(0))
}

pub async fn is_self_approval_disallowed(
    tx: &Transaction<'_>,
    tenant_id: Uuid,
    repository_id: Uuid,
    base_ref: &str,
    pull_author_id: Uuid,
) -> Result<bool, Error> {
    if pull_author_id != tenant_id {
        return Ok(true);
    }
    if has_self_approval_col(tx).await? {
        let prevent: Option<bool> = tx
            .query_opt(
                "SELECT prevent_self_approval FROM forge_branch_rules WHERE tenant_id=$1 AND repository_id=$2 AND branch_ref=$3",
                &[&tenant_id, &repository_id, &base_ref],
            )
            .await
            .map_err(Error::internal)?
            .map(|r| r.get(0));
        if prevent == Some(true) {
            return Ok(true);
        }
    }
    rbac::repo_has_collaborators_or_teams(tx, repository_id).await
}

pub async fn upsert_branch_rule(
    State(state): State<Arc<AppState>>,
    Path((owner, name)): Path<(String, String)>,
    headers: HeaderMap,
    Json(input): Json<BranchRuleInput>,
) -> Result<Response, Error> {
    let raw_branch = input.branch_ref.as_deref().ok_or_else(Error::bad_request)?;
    let branch_ref = normalize_branch_ref(raw_branch)?;
    upsert_branch_rule_inner(state, owner, name, branch_ref, headers, input).await
}

pub async fn put_branch_rule_by_path(
    State(state): State<Arc<AppState>>,
    Path((owner, name, branch)): Path<(String, String, String)>,
    headers: HeaderMap,
    Json(input): Json<BranchRuleInput>,
) -> Result<Response, Error> {
    let branch_ref = normalize_branch_ref(&branch)?;
    if let Some(ref body_branch) = input.branch_ref {
        if normalize_branch_ref(body_branch)? != branch_ref {
            return Err(Error::bad_request());
        }
    }
    upsert_branch_rule_inner(state, owner, name, branch_ref, headers, input).await
}

async fn upsert_branch_rule_inner(
    state: Arc<AppState>,
    owner: String,
    name: String,
    branch_ref: String,
    headers: HeaderMap,
    input: BranchRuleInput,
) -> Result<Response, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    if !(0..=100).contains(&input.required_approvals)
        || input.required_checks.len() > 64
        || input.expected_version.is_some_and(|v| v <= 0)
    {
        return Err(Error::bad_request());
    }
    let mut seen = HashSet::with_capacity(input.required_checks.len());
    for ctx in &input.required_checks {
        if !context_valid(ctx) || !seen.insert(ctx.as_str()) {
            return Err(Error::bad_request());
        }
    }
    let checks_json = serde_json::to_value(&input.required_checks).map_err(Error::internal)?;
    if checks_json.to_string().len() > 8192 {
        return Err(Error::bad_request());
    }

    let key = idempotency_key(&headers)?;
    let _policy_guard = policy_write_lock(&state, &owner, &name).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = auth::authorize_repo_with_role(&tx, &actor, &owner, &name, Role::Maintain).await?;
    let (repo, tenant_id) = (access.repo_id, access.owner_id);

    if let Some(key) = key {
        let mut request = serde_json::json!({
            "operation": "branch_rule",
            "branch_ref": branch_ref,
            "expected_version": input.expected_version,
            "required_approvals": input.required_approvals,
            "required_checks": input.required_checks,
            "require_fast_forward": input.require_fast_forward,
            "prevent_deletion": input.prevent_deletion,
            "prevent_force_push": input.prevent_force_push,
        });
        if input.prevent_self_approval {
            request["prevent_self_approval"] = Value::Bool(true);
        }
        if let Some(response) = creation_replay(&tx, tenant_id, repo, key, &request).await? {
            finish(tx, &actor, true).await?;
            let code = if input.expected_version.is_none() {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            };
            return Ok(json(code, response));
        }
    }

    let mut has_col = has_self_approval_col(&tx).await?;
    if input.prevent_self_approval && !has_col {
        tx.execute(
            "ALTER TABLE forge_branch_rules ADD COLUMN IF NOT EXISTS prevent_self_approval BOOLEAN NOT NULL DEFAULT false",
            &[],
        )
        .await
        .map_err(Error::internal)?;
        has_col = true;
    }

    let existing = tx
        .query_opt(
            "SELECT version FROM forge_branch_rules WHERE tenant_id=$1 AND repository_id=$2 AND branch_ref=$3 FOR UPDATE",
            &[&tenant_id, &repo, &branch_ref],
        )
        .await
        .map_err(Error::internal)?;

    let (status_code, row) = match existing {
        None => {
            if input.expected_version.is_some() {
                return Err(Error(StatusCode::CONFLICT, "branch rule version conflict"));
            }
            let inserted = if has_col {
                tx.query_one(
                    &format!("INSERT INTO forge_branch_rules (tenant_id,repository_id,branch_ref,required_approvals,required_checks,require_fast_forward,prevent_deletion,prevent_force_push,prevent_self_approval) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING {RULE_FIELDS},prevent_self_approval"),
                    &[&tenant_id, &repo, &branch_ref, &input.required_approvals, &checks_json, &input.require_fast_forward, &input.prevent_deletion, &input.prevent_force_push, &input.prevent_self_approval],
                )
                .await
                .map_err(Error::internal)?
            } else {
                tx.query_one(
                    &format!("INSERT INTO forge_branch_rules (tenant_id,repository_id,branch_ref,required_approvals,required_checks,require_fast_forward,prevent_deletion,prevent_force_push) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING {RULE_FIELDS}"),
                    &[&tenant_id, &repo, &branch_ref, &input.required_approvals, &checks_json, &input.require_fast_forward, &input.prevent_deletion, &input.prevent_force_push],
                )
                .await
                .map_err(Error::internal)?
            };
            (StatusCode::CREATED, inserted)
        }
        Some(cur) => {
            let current_version: i64 = cur.get("version");
            if input.expected_version != Some(current_version) {
                return Err(Error(StatusCode::CONFLICT, "branch rule version conflict"));
            }
            let updated = if has_col {
                tx.query_one(
                    &format!("UPDATE forge_branch_rules SET required_approvals=$4,required_checks=$5,require_fast_forward=$6,prevent_deletion=$7,prevent_force_push=$8,prevent_self_approval=$10,version=version+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND repository_id=$2 AND branch_ref=$3 AND version=$9 RETURNING {RULE_FIELDS},prevent_self_approval"),
                    &[&tenant_id, &repo, &branch_ref, &input.required_approvals, &checks_json, &input.require_fast_forward, &input.prevent_deletion, &input.prevent_force_push, &current_version, &input.prevent_self_approval],
                )
                .await
                .map_err(Error::internal)?
            } else {
                tx.query_one(
                    &format!("UPDATE forge_branch_rules SET required_approvals=$4,required_checks=$5,require_fast_forward=$6,prevent_deletion=$7,prevent_force_push=$8,version=version+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND repository_id=$2 AND branch_ref=$3 AND version=$9 RETURNING {RULE_FIELDS}"),
                    &[&tenant_id, &repo, &branch_ref, &input.required_approvals, &checks_json, &input.require_fast_forward, &input.prevent_deletion, &input.prevent_force_push, &current_version],
                )
                .await
                .map_err(Error::internal)?
            };
            (StatusCode::OK, updated)
        }
    };

    let rule = BranchRule::row(&row)?;
    let val = serde_json::to_value(&rule).map_err(Error::internal)?;
    record_creation(&tx, tenant_id, repo, key, &val).await?;
    audit::record_audit_event(
        &tx,
        tenant_id,
        repo,
        &actor,
        "branch_rule.upserted",
        "branch_rule",
        &branch_ref,
        serde_json::json!({
            "required_approvals": rule.required_approvals,
            "prevent_self_approval": rule.prevent_self_approval,
            "version": rule.version,
        }),
    )
    .await?;
    finish(tx, &actor, true).await?;
    Ok(json(status_code, val))
}

pub async fn list_branch_rules(
    State(state): State<Arc<AppState>>,
    Path((owner, name)): Path<(String, String)>,
    Query(page): Query<Page>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let (after, limit) = page.bounds()?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let repo = authorize(&tx, &actor, &owner, &name, false).await?;
    let tenant_id = repo_tenant_id(&tx, repo).await?;
    let fields = if has_self_approval_col(&tx).await? {
        format!("{RULE_FIELDS},prevent_self_approval")
    } else {
        RULE_FIELDS.to_owned()
    };
    let rows = tx
        .query(
            &format!("SELECT {fields} FROM forge_branch_rules WHERE tenant_id=$1 AND repository_id=$2 ORDER BY branch_ref ASC OFFSET $3 LIMIT $4"),
            &[&tenant_id, &repo, &after, &(limit + 1)],
        )
        .await
        .map_err(Error::internal)?;
    let more = rows.len() > limit as usize;
    let mut items = Vec::with_capacity(rows.len().min(limit as usize));
    for row in rows.iter().take(limit as usize) {
        items.push(BranchRule::row(row)?);
    }
    let next_after = if more { Some(after + limit) } else { None };
    finish(tx, &actor, false).await?;
    Ok(json(
        StatusCode::OK,
        serde_json::json!({ "items": items, "next_after": next_after }),
    ))
}

pub async fn get_branch_rule(
    State(state): State<Arc<AppState>>,
    Path((owner, name, branch)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let branch_ref = normalize_branch_ref(&branch)?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let repo = authorize(&tx, &actor, &owner, &name, false).await?;
    let tenant_id = repo_tenant_id(&tx, repo).await?;
    let fields = if has_self_approval_col(&tx).await? {
        format!("{RULE_FIELDS},prevent_self_approval")
    } else {
        RULE_FIELDS.to_owned()
    };
    let row = tx
        .query_opt(
            &format!("SELECT {fields} FROM forge_branch_rules WHERE tenant_id=$1 AND repository_id=$2 AND branch_ref=$3"),
            &[&tenant_id, &repo, &branch_ref],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    let rule = BranchRule::row(&row)?;
    finish(tx, &actor, false).await?;
    Ok(json(StatusCode::OK, rule))
}

pub async fn delete_branch_rule(
    State(state): State<Arc<AppState>>,
    Path((owner, name, branch)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let branch_ref = normalize_branch_ref(&branch)?;
    let _policy_guard = policy_write_lock(&state, &owner, &name).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = auth::authorize_repo_with_role(&tx, &actor, &owner, &name, Role::Maintain).await?;
    let (repo, tenant_id) = (access.repo_id, access.owner_id);
    let deleted = tx
        .execute(
            "DELETE FROM forge_branch_rules WHERE tenant_id=$1 AND repository_id=$2 AND branch_ref=$3",
            &[&tenant_id, &repo, &branch_ref],
        )
        .await
        .map_err(Error::internal)?;
    if deleted == 0 {
        return Err(Error::not_found());
    }
    audit::record_audit_event(
        &tx,
        tenant_id,
        repo,
        &actor,
        "branch_rule.deleted",
        "branch_rule",
        &branch_ref,
        serde_json::json!({ "branch_ref": branch_ref }),
    )
    .await?;
    finish(tx, &actor, true).await?;
    Ok(json(
        StatusCode::OK,
        serde_json::json!({ "deleted": true, "branch_ref": branch_ref }),
    ))
}

pub async fn evaluate_branch_policy(
    tx: &Transaction<'_>,
    tenant_id: Uuid,
    repository_id: Uuid,
    pull_number: i64,
    base_ref: &str,
    head_oid: &str,
) -> Result<PolicyEvaluation, Error> {
    let (tenant_id, pull_author_id, candidate_base): (Uuid, Uuid, Option<String>) = match tx
        .query_opt(
            "SELECT tenant_id, author_id, base_oid FROM forge_pulls WHERE repository_id=$1 AND number=$2",
            &[&repository_id, &pull_number],
        )
        .await
        .map_err(Error::internal)?
    {
        Some(r) => (r.get("tenant_id"), r.get("author_id"),Some(r.get("base_oid"))),
        None => (tenant_id, tenant_id,None),
    };

    let rule_row = tx
        .query_opt(
            "SELECT required_approvals, required_checks, require_fast_forward FROM forge_branch_rules WHERE tenant_id=$1 AND repository_id=$2 AND branch_ref=$3",
            &[&tenant_id, &repository_id, &base_ref],
        )
        .await
        .map_err(Error::internal)?;

    let Some(rule_row) = rule_row else {
        return Ok(PolicyEvaluation {
            allowed: true,
            require_fast_forward: false,
            required_approvals: 0,
            current_approvals: 0,
            required_checks: Vec::new(),
            missing_or_failed_checks: Vec::new(),
            reason: None,
        });
    };

    let required_approvals: i64 = rule_row.get("required_approvals");
    let checks_val: Value = rule_row.get("required_checks");
    let required_checks: Vec<String> =
        serde_json::from_value(checks_val).map_err(Error::internal)?;
    let require_fast_forward: bool = rule_row.get("require_fast_forward");

    let latest_verdict = tx
        .query_opt(
            "SELECT state FROM forge_pull_reviews WHERE tenant_id=$1 AND repository_id=$2 AND pull_number=$3 AND commit_oid=$4 AND state IN ('approved', 'changes_requested') ORDER BY number DESC LIMIT 1",
            &[&tenant_id, &repository_id, &pull_number, &head_oid],
        )
        .await
        .map_err(Error::internal)?
        .map(|r| r.get::<_, String>("state"));

    let approval_count: i64 = tx
        .query_one(
            "SELECT count(*) FROM forge_pull_reviews \
             WHERE tenant_id=$1 AND repository_id=$2 AND pull_number=$3 AND commit_oid=$4 AND state='approved' \
               AND number > COALESCE((SELECT max(number) FROM forge_pull_reviews WHERE tenant_id=$1 AND repository_id=$2 AND pull_number=$3 AND commit_oid=$4 AND state='changes_requested'), 0)",
            &[&tenant_id, &repository_id, &pull_number, &head_oid],
        )
        .await
        .map_err(Error::internal)?
        .get(0);

    let disallow_self =
        is_self_approval_disallowed(tx, tenant_id, repository_id, base_ref, pull_author_id).await?;
    let effective_approvals = if disallow_self {
        let rows = tx
            .query(
                "SELECT author_id FROM forge_pull_reviews \
                 WHERE tenant_id=$1 AND repository_id=$2 AND pull_number=$3 AND commit_oid=$4 AND state='approved' \
                   AND number > COALESCE((SELECT max(number) FROM forge_pull_reviews WHERE tenant_id=$1 AND repository_id=$2 AND pull_number=$3 AND commit_oid=$4 AND state='changes_requested'), 0)",
                &[&tenant_id, &repository_id, &pull_number, &head_oid],
            )
            .await
            .map_err(Error::internal)?;
        let mut distinct_approvers = HashSet::new();
        for r in rows {
            let reviewer_id: Uuid = r.get("author_id");
            if reviewer_id == pull_author_id {
                continue;
            }
            if let Some(role) =
                rbac::resolve_effective_role_by_id(tx, repository_id, tenant_id, reviewer_id)
                    .await?
            {
                if role >= Role::Write {
                    distinct_approvers.insert(reviewer_id);
                }
            }
        }
        distinct_approvers.len() as i64
    } else {
        approval_count
    };

    let current_approvals = if latest_verdict.as_deref() == Some("changes_requested") {
        0
    } else {
        effective_approvals
    };

    let mut missing_or_failed_checks = Vec::new();
    for ctx in &required_checks {
        let passed = crate::webhooks::trust::trusted_check_passed(
            &**tx, repository_id, head_oid, ctx, candidate_base.as_deref(),
        ).await?;
        if !passed {
            missing_or_failed_checks.push(ctx.clone());
        }
    }

    let mut allowed = true;
    let mut reason = None;
    if latest_verdict.as_deref() == Some("changes_requested") && required_approvals > 0 {
        allowed = false;
        reason = Some("changes requested on pull request");
    } else if current_approvals < required_approvals {
        allowed = false;
        reason = Some("insufficient pull request approvals");
    } else if !missing_or_failed_checks.is_empty() {
        allowed = false;
        reason = Some("required check runs have not succeeded");
    }

    Ok(PolicyEvaluation {
        allowed,
        require_fast_forward,
        required_approvals,
        current_approvals,
        required_checks,
        missing_or_failed_checks,
        reason,
    })
}
