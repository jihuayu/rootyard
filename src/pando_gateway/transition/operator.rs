//! Offline operator surface for two-phase backend transitions.
//!
//! Status and abandoned-drain recovery are PostgreSQL-only and keep the durable
//! fence closed. Cutover and rollback open the data volume exclusively, so they
//! cannot run beside a live server that owns the same volume.
use super::{TransitionReport, cutover, fence, rollback};
use crate::{
    AppState, Error,
    config::Config,
    db::{self, Repository},
    dispatch, metrics,
    storage::Storage,
};
use anyhow::{Context, Result, ensure};
use axum::http::StatusCode;
use deadpool_postgres::Pool;
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
use tokio::time::Instant;
use uuid::Uuid;

fn conflict(message: &'static str) -> Error {
    Error(StatusCode::CONFLICT, message)
}

fn parse_uuid(value: &str, name: &str) -> Result<Uuid> {
    value.parse().with_context(|| format!("invalid {name} UUID"))
}

fn flag<'a>(args: &'a [String], name: &str) -> Result<&'a str> {
    let matches: Vec<_> = args.iter().enumerate().filter(|(_, value)| value.as_str() == name).collect();
    ensure!(matches.len() == 1, "each option must appear exactly once: {name}");
    let index = matches[0].0;
    let value = args.get(index + 1).context(format!("missing value for {name}"))?;
    ensure!(!value.starts_with("--"), "missing value for {name}");
    Ok(value)
}

/// Read the durable fence without touching the data volume.
pub async fn status(pool: &Pool, repository_id: Uuid) -> Result<Value> {
    let row = pool
        .get()
        .await?
        .query_opt(
            "SELECT state,recovery_reason,storage_backend,storage_generation,transition_state,
             transition_id,backend_transition_epoch,transition_started_at::text,transition_error
             FROM repositories WHERE id=$1",
            &[&repository_id],
        )
        .await?
        .context("repository not found")?;
    Ok(json!({
        "version": 1,
        "repository_id": repository_id,
        "state": row.get::<_, String>(0),
        "recovery_reason": row.get::<_, Option<String>>(1),
        "storage_backend": row.get::<_, String>(2),
        "storage_generation": row.get::<_, i64>(3),
        "transition_state": row.get::<_, String>(4),
        "transition_id": row.get::<_, Option<Uuid>>(5),
        "transition_epoch": row.get::<_, i64>(6),
        "transition_started_at": row.get::<_, Option<String>>(7),
        "transition_error": row.get::<_, Option<String>>(8),
    }))
}

/// Close an abandoned `draining` fence to `failed`, never `stable`.
///
/// The caller must prove the exact transition identity, epoch, backend and
/// generation it observed. The publication advisory lock is taken first, so an
/// active publisher or transition rejects the command instead of being
/// unfenced. Ordinary writes stay blocked in `failed`; a same-direction retry
/// may then begin and complete normally.
pub async fn recover_abandoned_draining(
    config: &Config,
    pool: &Pool,
    repository_id: Uuid,
    expected_transition: Uuid,
    expected_epoch: i64,
    expected_backend: &str,
    expected_generation: i64,
) -> std::result::Result<Value, Error> {
    if !matches!(expected_backend, "gitfs" | "pando") || expected_epoch <= 0 || expected_generation <= 0 {
        return Err(Error(StatusCode::BAD_REQUEST, "invalid expected transition identity"));
    }
    // Offline recovery owns the volume exclusively, so it cannot race a live
    // server's local writer even before reaching the publication lock.
    let _volume = Storage::open(config).map_err(|_| Error(StatusCode::CONFLICT, "data volume is in use"))?;
    let publication = fence::acquire_publication_lock(pool, repository_id, Instant::now() + Duration::from_secs(1))
        .await
        .map_err(|_| conflict("active publisher or transition prevents abandoned-drain recovery"))?;
    let result: std::result::Result<Value, Error> = async {
        let mut client = pool.get().await.map_err(Error::internal)?;
        let tx = client.transaction().await.map_err(Error::internal)?;
        let row = tx
            .query_opt(
                "SELECT state,storage_backend,storage_generation,transition_state,transition_id,
                 backend_transition_epoch FROM repositories WHERE id=$1 FOR UPDATE",
                &[&repository_id],
            )
            .await
            .map_err(Error::internal)?
            .ok_or_else(Error::not_found)?;
        if row.get::<_, String>(0) != "ready"
            || row.get::<_, String>(3) != "draining"
            || row.get::<_, Option<Uuid>>(4) != Some(expected_transition)
            || row.get::<_, i64>(5) != expected_epoch
            || row.get::<_, String>(1) != expected_backend
            || row.get::<_, i64>(2) != expected_generation
        {
            return Err(conflict("repository transition identity changed; inspect again"));
        }
        let message = format!(
            "operator recovered abandoned draining transition {expected_transition} epoch {expected_epoch} from {expected_backend}"
        );
        let changed = tx
            .execute(
                "UPDATE repositories SET transition_state='failed',transition_error=$6
                 WHERE id=$1 AND transition_state='draining' AND transition_id=$2
                   AND backend_transition_epoch=$3 AND storage_backend=$4
                   AND storage_generation=$5 AND state='ready'",
                &[
                    &repository_id,
                    &expected_transition,
                    &expected_epoch,
                    &expected_backend,
                    &expected_generation,
                    &message,
                ],
            )
            .await
            .map_err(Error::internal)?;
        if changed != 1 {
            return Err(conflict("repository transition identity changed; inspect again"));
        }
        tx.commit().await.map_err(Error::internal)?;
        Ok(json!({
            "version": 1,
            "repository_id": repository_id,
            "transition_state": "failed",
            "transition_id": expected_transition,
            "transition_epoch": expected_epoch,
            "storage_backend": expected_backend,
            "storage_generation": expected_generation,
            "transition_error": message,
            "effect": "ordinary writes stay fenced; retry the same transition after repairing the cause",
        }))
    }
    .await;
    fence::release_publication_lock(&publication, repository_id).await;
    result
}

async fn repository(pool: &Pool, repository_id: Uuid) -> std::result::Result<Repository, Error> {
    let row = pool
        .get()
        .await
        .map_err(Error::internal)?
        .query_opt(&format!("{} WHERE r.id=$1", db::REPO_SELECT), &[&repository_id])
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    Ok(Repository::from_row(&row))
}

async fn offline_state(config: &Config, pool: &Pool) -> std::result::Result<Arc<AppState>, Error> {
    // The exclusive data-directory lock is the offline writer barrier: a live
    // server that owns this volume makes Storage::open fail.
    let storage = Storage::open(config).map_err(|_| Error(StatusCode::CONFLICT, "data volume is in use"))?;
    Ok(Arc::new(AppState {
        mirror_primary: None,
        dispatch: dispatch::Signals::default(),
        storage,
        config: config.clone(),
        pool: pool.clone(),
        hooks: None,
        transfer_metrics: Arc::new(metrics::TransferCounters::default()),
        git_slots: Arc::new(tokio::sync::Semaphore::new(1)),
    }))
}

async fn run_transition(config: &Config, pool: &Pool, repository_id: Uuid, reverse: bool) -> Result<Value> {
    let state = offline_state(config, pool).await.map_err(|error| anyhow::anyhow!(error.1))?;
    let repo = repository(pool, repository_id).await.map_err(|error| anyhow::anyhow!(error.1))?;
    let deadline = Instant::now() + config.git_timeout.max(Duration::from_secs(600));
    let report: TransitionReport = if reverse {
        rollback(&state, &repo, deadline).await.map_err(|error| anyhow::anyhow!(error.1))?
    } else {
        cutover(&state, &repo, deadline).await.map_err(|error| anyhow::anyhow!(error.1))?
    };
    Ok(serde_json::to_value(report)?)
}

/// Entry point used by `rootyard pando-transition ...`.
pub async fn cli(config: &Config, pool: &Pool, args: &[String]) -> Result<()> {
    let command = args.first().map(String::as_str).context("missing pando-transition command")?;
    let repository_id = parse_uuid(flag(args, "--repository")?, "repository")?;
    let output = match command {
        "status" => status(pool, repository_id).await?,
        "cutover" => run_transition(config, pool, repository_id, false).await?,
        "rollback" => run_transition(config, pool, repository_id, true).await?,
        "recover-abandoned-draining" => {
            let transition = parse_uuid(flag(args, "--expected-transition")?, "transition")?;
            let epoch: i64 = flag(args, "--expected-epoch")?.parse().context("invalid expected epoch")?;
            let backend = flag(args, "--expected-backend")?;
            let generation: i64 =
                flag(args, "--expected-generation")?.parse().context("invalid expected generation")?;
            recover_abandoned_draining(config, pool, repository_id, transition, epoch, backend, generation)
                .await
                .map_err(|error| anyhow::anyhow!(error.1))?
        }
        _ => anyhow::bail!("unsupported pando-transition command: {command}"),
    };
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}
