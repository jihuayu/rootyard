//! Durable polling repairs lost wakeups and progresses webhook retries without an API call.
use crate::{AppState, Error, pulls::models::{PULL_FIELDS, PullRequest, resolve_ref_oid}, webhooks::delivery::{current_unix_seconds, dispatch_due_deliveries, on_pull_synchronized, sync_outbox_events, sync_pull_events}};
use std::{sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Scan state held in PostgreSQL; a wake only shortens latency. Failures leave rows
/// eligible for the next scan and are surfaced once per outage in the worker log.
pub async fn worker(state: Arc<AppState>, stop: CancellationToken) {
    let mut tick = tokio::time::interval(Duration::from_secs(2));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut unavailable = false;
    loop {
        tokio::select! {
            _ = stop.cancelled() => break,
            _ = tick.tick() => {},
            _ = state.dispatch.local.notified() => {},
        }
        let result = tokio::select! {
            _ = stop.cancelled() => break,
            result = tokio::time::timeout(Duration::from_secs(60), scan_once(&state)) => result,
        };
        let failed = !matches!(result, Ok(Ok(())));
        if failed && !unavailable {
            eprintln!("rootyard: webhook synchronization unavailable; durable retry scheduled");
        }
        unavailable = failed;
        tokio::select! { _ = stop.cancelled() => break, _ = tokio::time::sleep(Duration::from_millis(25)) => {} }
    }
}

pub async fn scan_once(state: &AppState) -> Result<(), Error> {
    let client = state.pool.get().await.map_err(Error::internal)?;
    let rows = client.query(
        "SELECT DISTINCT tenant_id,repository_id FROM forge_webhooks WHERE active=true \
         ORDER BY tenant_id,repository_id", &[])
        .await.map_err(Error::internal)?;
    drop(client);
    for row in rows {
        let tenant: Uuid = row.get(0);
        let repo: Uuid = row.get(1);
        reconcile_pull_refs(state, tenant, repo).await?;
        repair_pull_orchestration(state, tenant, repo).await?;
        sync_pull_events(state, tenant, repo).await?;
        // Missing-delivery selection makes each batch advance, including new hooks.
        loop {
            if sync_outbox_events(state, tenant, repo).await? == 0 { break; }
        }
        let now = current_unix_seconds();
        dispatch_due_deliveries(state, tenant, repo, 200, now).await?;
    }
    Ok(())
}

/// Recover a PR whose row advanced but whose pin, runs, or deliveries did not
/// finish. The marker is written last, after every idempotent side effect.
async fn repair_pull_orchestration(state:&AppState,tenant:Uuid,repo:Uuid)->Result<(),Error>{
    let client=state.pool.get().await.map_err(Error::internal)?;
    let rows=client.query(&format!("SELECT {PULL_FIELDS} FROM forge_pulls p \
        WHERE p.tenant_id=$1 AND p.repository_id=$2 AND p.state='open' AND NOT EXISTS( \
          SELECT 1 FROM ci_pull_sync_progress s WHERE s.repository_id=p.repository_id \
            AND s.pull_number=p.number AND s.pull_version=p.version \
            AND s.head_oid=p.head_oid AND s.base_oid=p.base_oid \
            AND s.storage_generation=(SELECT storage_generation FROM repositories \
              WHERE id=p.repository_id)) ORDER BY p.number LIMIT 100"),
        &[&tenant,&repo]).await.map_err(Error::internal)?;
    drop(client);
    for row in rows {
        let pull=PullRequest::row(&row);
        let action=if pull.version==1 {"opened"} else {"synchronize"};
        on_pull_synchronized(state,repo,&pull,action).await?;
    }
    Ok(())
}

/// Authoritative Git refs advance an open PR's immutable candidate version after push.
/// The optimistic version guard prevents replacing a concurrent user edit.
async fn reconcile_pull_refs(state: &AppState, tenant: Uuid, repo: Uuid) -> Result<(), Error> {
    let client = state.pool.get().await.map_err(Error::internal)?;
    let sql = format!("SELECT {PULL_FIELDS} FROM forge_pulls WHERE tenant_id=$1 AND repository_id=$2 AND state='open'");
    let rows = client.query(&sql, &[&tenant, &repo]).await.map_err(Error::internal)?;
    drop(client);
    for row in rows {
        let pull = PullRequest::row(&row);
        let guard = tokio::time::timeout(state.config.git_timeout, state.storage.write_lock(repo))
            .await.map_err(|_| Error::timeout())?;
        let (Some(head), Some(base)) = (
            resolve_ref_oid(state, repo, &pull.head_ref).await?,
            resolve_ref_oid(state, repo, &pull.base_ref).await?,
        ) else { continue; };
        if head == pull.head_oid && base == pull.base_oid { continue; }
        let client = state.pool.get().await.map_err(Error::internal)?;
        let sql = format!("UPDATE forge_pulls SET head_oid=$5,base_oid=$6,version=version+1,updated_at=clock_timestamp() \
            WHERE tenant_id=$1 AND repository_id=$2 AND number=$3 AND version=$4 AND state='open' RETURNING {PULL_FIELDS}");
        let updated = client.query_opt(&sql,
            &[&tenant,&repo,&pull.number,&pull.version,&head,&base]).await.map_err(Error::internal)?;
        drop(client);
        drop(guard);
        if let Some(updated) = updated {
            on_pull_synchronized(state, repo, &PullRequest::row(&updated), "synchronize").await?;
        }
    }
    Ok(())
}
