//! Outbox and Pull Request event ingestion, deterministic CI Source Pin + `queued` Check Run
//! orchestration (`on_pull_synchronized`), and SSRF-safe HTTP/1.1 delivery with exponential backoff.
use crate::{
    AppState, Error, ci_pins, db, events, git_http, journal,
    pulls::models::{PullRequest, resolve_ref_oid},
    reliability,
    webhooks::{
        claims,
        models::{WebhookDelivery, ensure_schema},
        signing::{build_delivery_headers, send_http11_webhook, signature_header},
    },
};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

pub const DEFAULT_BACKOFF_BASE_SECS: i64 = 2;
pub const DEFAULT_BACKOFF_MAX_SECS: i64 = 300;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PullCiOrchestration {
    pub pull_number: i64,
    pub head_oid: String,
    pub base_oid: String,
    pub job_id: Uuid,
    pub retention_ref: String,
    pub queued_contexts: Vec<String>,
    pub enqueued_deliveries: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DispatchSummary {
    pub synced_outbox_deliveries: usize,
    pub orchestrated_pulls: usize,
    pub attempted_deliveries: usize,
    pub delivered_count: usize,
    pub failed_count: usize,
    pub dead_letter_count: usize,
    pub deliveries: Vec<WebhookDelivery>,
}

pub fn current_unix_seconds() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Clock source for one delivery attempt. The manual API keeps `Fixed` so an
/// explicit `now_unix` remains a deterministic virtual clock. The background
/// worker uses `Wall` so a long batch cannot lease or back off from its start.
#[derive(Clone, Copy, Debug)]
pub(crate) enum DeliveryClock {
    Fixed(i64),
    Wall,
}

impl DeliveryClock {
    fn now(self) -> i64 {
        match self {
            Self::Fixed(now) => now,
            Self::Wall => current_unix_seconds(),
        }
    }
}

/// Computes exponential backoff delay `base_seconds * 2^(attempt - 1)` capped at `max_seconds`.
pub fn backoff_delay_seconds(attempt: i64, base_seconds: i64, max_seconds: i64) -> i64 {
    let base = base_seconds.max(1);
    let cap = max_seconds.max(base);
    let shift = attempt.saturating_sub(1).clamp(0, 30) as u32;
    base.saturating_mul(1i64.checked_shl(shift).unwrap_or(i64::MAX)).min(cap)
}

/// Derives a deterministic RFC 4122 UUID for a PR CI Source Pin.
pub fn pull_ci_job_id(repository_id: Uuid, pull_number: i64, head_oid: &str, storage_generation: i64) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(b"rootyard-pull-ci-pin-v1\0");
    hasher.update(repository_id.as_bytes());
    hasher.update(pull_number.to_be_bytes());
    hasher.update(storage_generation.to_be_bytes());
    hasher.update(head_oid.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

// The allocator and outbox scans live in `ingestion`; these facade exports keep
// the existing delivery API for handlers, background scheduling and callers.
pub(crate) use crate::webhooks::ingestion::sync_outbox_events_bounded;
pub use crate::webhooks::ingestion::{enqueue_webhook_delivery, sync_outbox_events, sync_pull_events};

#[rustfmt::skip]
pub(crate) async fn ensure_pull_ci_pin(
    state: &AppState,
    repo: &db::Repository,
    owner_id: Uuid,
    job_id: Uuid,
    head_oid: &str,
) -> Result<String, Error> {
    let retention_ref = format!("refs/rootyard-ci/jobs/{job_id}");
    let _slot = state.git_slots.clone().try_acquire_owned().map_err(|_| {
        Error(StatusCode::SERVICE_UNAVAILABLE, "Git capacity exhausted; retry later")
    })?;
    let publication = crate::storage::ref_publication::acquire(&state.pool,repo.id,
        repo.storage_generation,std::slice::from_ref(&retention_ref),
        tokio::time::Instant::now()+state.config.git_timeout).await?;
    let _write_guard = publication.enter_window(&state.storage,
        tokio::time::Instant::now()+state.config.git_timeout).await?;
    let _admission = crate::storage::admission::acquire(
        &state.pool,
        repo.id,
        repo.storage_generation,
        "ci-pin-webhook",
        tokio::time::Instant::now() + state.config.git_timeout,
    )
    .await?;
    reliability::ensure_gitfs_current(state, repo).await?;
    if state.hooks.is_some() {
        reliability::before_gitfs_push(state, repo).await?;
    }

    if !ci_pins::valid_format(&repo.object_format)
        || !ci_pins::valid_oid_for_format(head_oid, &repo.object_format)
    {
        return Err(Error(StatusCode::CONFLICT, "CI pin target format differs from repository"));
    }
    let intent = ci_pins::Intent {
        version: 1, job_id, owner_id, repository_id: repo.id,
        storage_generation: repo.storage_generation,
        object_format: repo.object_format.clone(),
        target_oid: head_oid.to_owned(), retention_ref: retention_ref.clone(),
    };
    let intent_bytes = serde_json::to_vec(&intent).map_err(Error::internal)?;
    let pins_root = state.storage.root.join("ci-pins");
    journal::mkdir(&pins_root).map_err(Error::internal)?;
    let repo_pins_dir = pins_root.join(repo.id.to_string());
    journal::mkdir(&repo_pins_dir).map_err(Error::internal)?;
    journal::atomic(&repo_pins_dir.join(format!("{job_id}.json")), &intent_bytes, false).map_err(Error::internal)?;

    let existing_ref = resolve_ref_oid(state, repo.id, &retention_ref).await?;
    if existing_ref.as_deref() != Some(head_oid) {
        let client = state.pool.get().await.map_err(Error::internal)?;
        client.execute("INSERT INTO ci_service_principals(id,repository_id,kind,active) \
            VALUES($1,$2,'ci-pin',true) ON CONFLICT(repository_id,kind) DO NOTHING",
            &[&Uuid::new_v4(),&repo.id]).await.map_err(Error::internal)?;
        let principal_id:Uuid=client.query_opt("SELECT id FROM ci_service_principals \
            WHERE repository_id=$1 AND kind='ci-pin' AND active=true",&[&repo.id])
            .await.map_err(Error::internal)?.ok_or_else(Error::unauthorized)?.get(0);
        drop(client);

        let repo_path = state.storage.verify_path(repo.id).map_err(Error::internal)?;
        let op = journal::begin_ci_service(&state.storage.root,&intent,principal_id)
            .map_err(Error::internal)?;
        let zero=crate::pulls::models::zero_oid(&repo.object_format).ok_or_else(||Error::internal("invalid repository object format"))?;
        let old_expected = existing_ref.as_deref().unwrap_or(&zero);
        let mut update_cmd = state.storage.git(&state.config);
        update_cmd
            .args(["-c", "core.hooksPath=/dev/null", "--no-replace-objects", "--git-dir"])
            .arg(&repo_path)
            .args(["update-ref", "--no-deref", &retention_ref, head_oid, old_expected]);
        if let Err(err) = git_http::collect_git_output(update_cmd, 4096, state.config.git_timeout).await {
            let _ = journal::finish(&op);
            let _ = journal::retire(&op);
            return Err(Error::internal(err));
        }
        journal::finish(&op).map_err(Error::internal)?;

        let changes = vec![events::RefEventInput {
            transaction_sequence: 1, ref_name: retention_ref.clone(),
            old_oid: old_expected.to_owned(), new_oid: head_oid.to_owned(),
        }];
        let evidence = json!({
            "version": 1, "kind": "observed_immutable_ci_root", "intent": intent,
            "finished": true, "interrupted": false, "reference_events": [], "retained": true,
        });
        let record = events::OperationRecord {
            id: op.id, repository_id: repo.id, actor_id: op.actor_id, token_id: op.token_id,
            service_principal_id: op.service_principal_id,
            actor_name: op.actor_name.clone(), sequence: op.sequence,
            storage_generation: repo.storage_generation, outcome: "recorded".into(), evidence,
            admission: None,
        };
        events::publish(&state.pool, &record, &changes).await.map_err(Error::internal)?;
        state.dispatch.committed();
        journal::retire(&op).map_err(Error::internal)?;
    }

    journal::atomic(&repo_pins_dir.join(format!("{job_id}.pinned.json")), &intent_bytes, false)
        .map_err(Error::internal)?;
    Ok(retention_ref)
}

/// Automatically creates a deterministic CI Source Pin (`refs/rootyard-ci/jobs/{job_id}`),
/// registers pending `queued` Check Runs for `pull.head_oid`, and enqueues signed `pull_request`
/// webhook deliveries.
#[rustfmt::skip]
pub async fn on_pull_synchronized(
    state: &AppState,
    repository_id: Uuid,
    pull: &PullRequest,
    action: &str,
) -> Result<PullCiOrchestration, Error> {
    ensure_schema(&state.pool).await?;
    let client = state.pool.get().await.map_err(Error::internal)?;
    let repo_row = client
        .query_opt(
            &format!("{} WHERE r.id=$1", db::REPO_SELECT),
            &[&repository_id],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    let tenant_id: Uuid = repo_row.get("owner_id");
    let repo = db::Repository::from_row(&repo_row);
    drop(client);

    let job_id = pull_ci_job_id(repository_id, pull.number, &pull.head_oid, repo.storage_generation);
    let retention_ref = if pull.state == "open" {
        ensure_pull_ci_pin(state, &repo, tenant_id, job_id, &pull.head_oid).await?
    } else {
        format!("refs/rootyard-ci/jobs/{job_id}")
    };

    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let mut contexts: Vec<String> = Vec::new();
    if let Some(rule_row) = client
        .query_opt("SELECT required_checks FROM forge_branch_rules WHERE tenant_id=$1 AND repository_id=$2 AND branch_ref=$3", &[&tenant_id, &repository_id, &pull.base_ref])
        .await
        .map_err(Error::internal)?
        && let Some(arr) = rule_row.get::<_, Value>("required_checks").as_array() {
            for ctx in arr.iter().filter_map(Value::as_str) {
                if !contexts.iter().any(|c| c == ctx) {
                    contexts.push(ctx.to_owned());
                }
            }
        }

    let hooks = client
        .query(
            "SELECT id, secret, max_attempts, events, ci_contexts, auto_ci_pin FROM forge_webhooks WHERE tenant_id=$1 AND repository_id=$2 AND active=true ORDER BY created_at ASC, id ASC",
            &[&tenant_id, &repository_id],
        )
        .await
        .map_err(Error::internal)?;

    for hook in &hooks {
        if hook.get::<_, bool>("auto_ci_pin")
            && let Some(arr) = hook.get::<_, Value>("ci_contexts").as_array() {
                for ctx in arr.iter().filter_map(Value::as_str) {
                    if !contexts.iter().any(|c| c == ctx) {
                        contexts.push(ctx.to_owned());
                    }
                }
            }
    }
    if contexts.is_empty() {
        contexts.push("ci/default".to_owned());
    }

    if pull.state == "open" {
        for ctx in &contexts {
            let config_sha256 = hex::encode(Sha256::digest(format!("rootyard-ci-config-v1\0{ctx}").as_bytes()));
            client.execute(
                "UPDATE ci_runs SET state='cancelled',lease_generation=lease_generation+1,updated_at=clock_timestamp() \
                 WHERE repository_id=$1 AND pull_number=$2 AND context=$3 AND state IN ('queued','leased') \
                   AND (head_oid<>$4 OR base_oid<>$5 OR storage_generation<>$6)",
                &[&repository_id,&pull.number,ctx,&pull.head_oid,&pull.base_oid,&repo.storage_generation],
            ).await.map_err(Error::internal)?;
            client.execute(
                "INSERT INTO ci_runs (id,tenant_id,repository_id,pull_number,pull_version,context,job_id,head_oid,base_oid,storage_generation,config_sha256) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) \
                 ON CONFLICT (repository_id,pull_number,pull_version,context) DO NOTHING",
                &[&Uuid::new_v4(),&tenant_id,&repository_id,&pull.number,&pull.version,ctx,&job_id,
                  &pull.head_oid,&pull.base_oid,&repo.storage_generation,&config_sha256],
            ).await.map_err(Error::internal)?;
            client
                .execute(
                    "INSERT INTO forge_check_runs (tenant_id,repository_id,commit_oid,context,attempt,sequence,status,conclusion,output) \
                     VALUES ($1,$2,$3,$4,1,1,'queued',NULL,'queued by pull request synchronization') \
                     ON CONFLICT (tenant_id, repository_id, commit_oid, context) DO NOTHING",
                    &[&tenant_id, &repository_id, &pull.head_oid, ctx],
                )
                .await
                .map_err(Error::internal)?;
        }
    }

    let delivery_event_id = format!("pull:{}:{}:{}:{}", pull.number, pull.version, pull.head_oid, action);
    let payload = json!({
        "event": "pull_request", "action": action, "repository_id": repository_id,
        "pull_number": pull.number, "head_oid": pull.head_oid, "base_oid": pull.base_oid,
        "head_ref": pull.head_ref, "base_ref": pull.base_ref, "ci_job_id": job_id,
        "retention_ref": retention_ref, "required_checks": contexts, "pull_request": pull,
        "ci_pin": { "job_id": job_id, "retention_ref": retention_ref, "target_oid": pull.head_oid, "storage_generation": repo.storage_generation },
        "queued_checks": contexts,
    });

    let mut enqueued_deliveries = 0usize;
    for hook in &hooks {
        let subscribed = hook.get::<_, Value>("events").as_array().is_some_and(|arr| arr.iter().any(|v| v.as_str() == Some("pull_request")));
        if subscribed
            && enqueue_webhook_delivery(&mut client, tenant_id, repository_id, hook.get("id"), &hook.get::<_, String>("secret"), hook.get("max_attempts"), &delivery_event_id, "pull_request", &payload)
                .await?
                .is_some()
        {
            enqueued_deliveries += 1;
        }
    }

    client.execute(
        "INSERT INTO ci_pull_sync_progress(repository_id,pull_number,pull_version,head_oid,base_oid,storage_generation) \
         VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(repository_id,pull_number,pull_version) \
         DO UPDATE SET head_oid=excluded.head_oid,base_oid=excluded.base_oid, \
           storage_generation=excluded.storage_generation,completed_at=clock_timestamp()",
        &[&repository_id,&pull.number,&pull.version,&pull.head_oid,&pull.base_oid,&repo.storage_generation],
    ).await.map_err(Error::internal)?;

    Ok(PullCiOrchestration {
        pull_number: pull.number, head_oid: pull.head_oid.clone(), base_oid: pull.base_oid.clone(),
        job_id, retention_ref, queued_contexts: contexts, enqueued_deliveries,
    })
}

pub async fn orchestrate_pull_ci(
    state: &AppState,
    repository_id: Uuid,
    pull: &PullRequest,
    action: &str,
) -> Result<PullCiOrchestration, Error> {
    on_pull_synchronized(state, repository_id, pull, action).await
}

#[rustfmt::skip]
pub async fn deliver_single(
    state: &AppState,
    tenant_id: Uuid,
    repository_id: Uuid,
    delivery_id: Uuid,
    now_unix: i64,
) -> Result<WebhookDelivery, Error> {
    deliver_single_with_clock(
        state,
        tenant_id,
        repository_id,
        delivery_id,
        DeliveryClock::Fixed(now_unix),
    )
    .await
}

async fn deliver_single_with_clock(
    state: &AppState,
    tenant_id: Uuid,
    repository_id: Uuid,
    delivery_id: Uuid,
    clock: DeliveryClock,
) -> Result<WebhookDelivery, Error> {
    let attempt_now = clock.now();
    let client = state.pool.get().await.map_err(Error::internal)?;
    let Some(claim) = claims::claim(&client, tenant_id, repository_id, delivery_id, attempt_now).await? else {
        return claims::current(&client, tenant_id, repository_id, delivery_id).await;
    };
    let webhook_id = claim.webhook_id;
    let event_type = claim.event_type;
    let payload = claim.payload;
    let attempt = claim.attempt;
    let max_attempts = claim.max_attempts;
    let url = claim.url;
    let secret = claim.secret;
    let timeout_ms = claim.timeout_ms;

    let body_bytes = serde_json::to_vec(&payload).map_err(Error::internal)?;
    let sig = signature_header(&secret, &body_bytes);
    let req_headers = build_delivery_headers(&event_type, delivery_id, webhook_id, attempt, &sig);

    let outcome =
        send_http11_webhook(&url, timeout_ms, &event_type, delivery_id, webhook_id, attempt, &sig, &body_bytes).await;
    // The transport may consume the whole timeout. Schedule from completion,
    // never from the batch timestamp that selected this delivery.
    let completed_now = clock.now();
    let (next_state, status_opt, err_opt, next_unix, delivered) = match outcome {
        Ok(code) if (200..=299).contains(&code) => ("delivered", Some(code as i32), None, 0i64, true),
        Ok(code) => {
            let (st, nu) = if attempt >= max_attempts {
                ("dead_letter", 0i64)
            } else {
                (
                    "failed",
                    completed_now.saturating_add(backoff_delay_seconds(
                        attempt,
                        DEFAULT_BACKOFF_BASE_SECS,
                        DEFAULT_BACKOFF_MAX_SECS,
                    )),
                )
            };
            (st, Some(code as i32), Some(format!("HTTP {code}")), nu, false)
        }
        Err(err_msg) => {
            let (st, nu) = if attempt >= max_attempts {
                ("dead_letter", 0i64)
            } else {
                (
                    "failed",
                    completed_now.saturating_add(backoff_delay_seconds(
                        attempt,
                        DEFAULT_BACKOFF_BASE_SECS,
                        DEFAULT_BACKOFF_MAX_SECS,
                    )),
                )
            };
            (st, None, Some(err_msg), nu, false)
        }
    };

    claims::complete(
        &client,
        tenant_id,
        repository_id,
        delivery_id,
        claim.generation,
        next_state,
        &req_headers,
        &sig,
        status_opt,
        err_opt,
        next_unix,
        delivered,
    )
    .await
}

#[rustfmt::skip]
async fn due_delivery_ids(
    state: &AppState,
    tenant_id: Uuid,
    repository_id: Uuid,
    limit: i64,
    now_unix: i64,
) -> Result<Vec<Uuid>, Error> {
    let client = state.pool.get().await.map_err(Error::internal)?;
    let rows = client
        .query(
            "SELECT d.id FROM forge_webhook_deliveries d JOIN forge_webhooks w ON w.id = d.webhook_id \
             WHERE d.tenant_id=$1 AND d.repository_id=$2 AND w.active=true \
               AND (d.state='pending' OR (d.state IN ('failed','leased') AND d.next_attempt_unix <= $3)) \
             ORDER BY d.sequence ASC LIMIT $4",
            &[&tenant_id, &repository_id, &now_unix, &limit],
        )
        .await
        .map_err(Error::internal)?;
    Ok(rows.iter().map(|row| row.get("id")).collect())
}

/// Manual and compatibility path. `now_unix` is a caller-supplied virtual
/// clock used for both selection and each attempt, preserving deterministic
/// tests and the documented dispatch contract.
#[rustfmt::skip]
pub async fn dispatch_due_deliveries(
    state: &AppState,
    tenant_id: Uuid,
    repository_id: Uuid,
    limit: i64,
    now_unix: i64,
) -> Result<Vec<WebhookDelivery>, Error> {
    dispatch_due_deliveries_with(state, tenant_id, repository_id, limit, now_unix,
        DeliveryClock::Fixed(now_unix),
        tokio::time::Instant::now() + std::time::Duration::from_secs(86_400)).await
}

/// Background path. Selection uses `select_now_unix`, but every claim and
/// completion reads the wall clock independently, so an old batch timestamp
/// cannot grant a stale lease or schedule a retry in the past. Stop starting new
/// sends after `work_deadline`; never cancel one that has already started, so
/// the hook's declared transport timeout governs the in-flight request.
#[rustfmt::skip]
pub(crate) async fn dispatch_due_deliveries_until(
    state: &AppState,
    tenant_id: Uuid,
    repository_id: Uuid,
    limit: i64,
    select_now_unix: i64,
    work_deadline: tokio::time::Instant,
) -> Result<Vec<WebhookDelivery>, Error> {
    dispatch_due_deliveries_with(state, tenant_id, repository_id, limit, select_now_unix,
        DeliveryClock::Wall, work_deadline).await
}

#[rustfmt::skip]
async fn dispatch_due_deliveries_with(
    state: &AppState,
    tenant_id: Uuid,
    repository_id: Uuid,
    limit: i64,
    select_now_unix: i64,
    clock: DeliveryClock,
    work_deadline: tokio::time::Instant,
) -> Result<Vec<WebhookDelivery>, Error> {
    if tokio::time::Instant::now() >= work_deadline {
        return Ok(Vec::new());
    }
    let ids = due_delivery_ids(state, tenant_id, repository_id, limit, select_now_unix).await?;
    let mut out = Vec::with_capacity(ids.len());
    for delivery_id in ids {
        if tokio::time::Instant::now() >= work_deadline {
            break;
        }
        out.push(deliver_single_with_clock(state, tenant_id, repository_id, delivery_id, clock).await?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exponential_backoff_schedule_and_deterministic_ci_job_uuid() {
        assert_eq!(backoff_delay_seconds(1, 2, 300), 2);
        assert_eq!(backoff_delay_seconds(2, 2, 300), 4);
        assert_eq!(backoff_delay_seconds(3, 2, 300), 8);
        assert_eq!(backoff_delay_seconds(4, 2, 300), 16);
        assert_eq!(backoff_delay_seconds(10, 2, 300), 300);

        let repo_id = Uuid::new_v4();
        let oid1 = "1111111111111111111111111111111111111111";
        let oid2 = "2222222222222222222222222222222222222222";
        assert_eq!(pull_ci_job_id(repo_id, 1, oid1, 1), pull_ci_job_id(repo_id, 1, oid1, 1));
        assert_ne!(pull_ci_job_id(repo_id, 1, oid1, 1), pull_ci_job_id(repo_id, 1, oid2, 1));
    }
}
