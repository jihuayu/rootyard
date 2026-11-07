use anyhow::{Context, Result, bail};
use rootyard::{AppState, config::Config, db, storage::Storage};
use std::sync::Arc;

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() == 2 && args[1] == "--rootyard-hook-self-check" {
        println!("rootyard-hook-v1");
        return Ok(());
    }
    let name = std::path::Path::new(&args[0]).file_name().and_then(|v| v.to_str()).unwrap_or("");
    match name {
        "reference-transaction" => {
            return rootyard::journal::run_hook(args.get(1).map(String::as_str).unwrap_or(""));
        }
        "post-receive" => return rootyard::journal::run_post_receive(),
        "pre-receive" => return rootyard::journal::run_pre_receive(),
        _ => {}
    }
    tokio::runtime::Builder::new_multi_thread().enable_all().build()?.block_on(run())
}
async fn run() -> Result<()> {
    if !cfg!(target_os = "linux") {
        bail!("Rootyard phase one currently supports Linux only");
    }
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.first().is_some_and(|s| s == "backup-verify") && args.len() == 2 {
        return rootyard::backup::check(std::path::Path::new(&args[1]))
            .map_err(|_| anyhow::anyhow!("backup verification failed; incomplete, unsafe or mismatched files"));
    }
    // Control-plane workers need only PostgreSQL, never Git or a data volume.
    if args.len() == 1 && matches!(args[0].as_str(), "worker" | "worker-once") {
        let url = std::env::var("DATABASE_URL").context("DATABASE_URL is required")?;
        let pool = db::pool(&url)?;
        db::prepare_runtime_schema(&pool).await?;
        let settings = rootyard::dispatch::Settings::from_env()?;
        if args[0] == "worker-once" {
            let owner = uuid::Uuid::new_v4();
            let mut count = 0;
            for consumer in &settings.consumers {
                count += rootyard::events::worker_once_with_lease(
                    &pool,
                    consumer,
                    owner,
                    settings.batch,
                    settings.lease_seconds,
                )
                .await?;
            }
            println!("{count}");
        } else {
            let stop = tokio_util::sync::CancellationToken::new();
            let mut task = tokio::spawn(rootyard::dispatch::worker(
                pool,
                settings,
                Arc::new(tokio::sync::Notify::new()),
                stop.clone(),
            ));
            eprintln!("rootyard: PostgreSQL delivery worker started (no Git storage access)");
            tokio::select! {
                _=shutdown()=>{ stop.cancel(); task.await?; },
                result=&mut task=>{ result?; bail!("delivery worker stopped unexpectedly"); },
            }
        }
        return Ok(());
    }
    let config = Config::from_env()?;
    let pool = db::pool(&config.database_url)?;
    match args.first().map(String::as_str).unwrap_or("serve") {
        "backup" if args.len() == 3 && args[2] == "--offline" => {
            rootyard::backup::create(&config, std::path::Path::new(&args[1])).await
                .map_err(|_| anyhow::anyhow!("backup failed; requires stopped writers, supported dedicated database and safe new destination; partial files may remain"))?;
        }
        "restore"
            if (args.len() == 4
                || (args.len() == 5
                    && matches!(
                        args[4].as_str(),
                        "--allow-legacy-schema007" | "--allow-legacy-schema130" | "--allow-legacy-schema131"
                    )))
                && args[2] == "--isolated"
                && args[3] == "--trust-backup" =>
        {
            let legacy = args.get(4).map(String::as_str);
            rootyard::backup::restore(
                &config,
                std::path::Path::new(&args[1]),
                legacy == Some("--allow-legacy-schema007"),
                legacy == Some("--allow-legacy-schema130"),
                legacy == Some("--allow-legacy-schema131"),
            )
            .await
            .map_err(|_| anyhow::anyhow!("restore failed; keep target isolated and inspect or discard the fresh targets; database commit may have completed; never retry over existing state"))?;
        }
        "migrate" if args.len() == 1 => {
            db::migrate(&pool).await?;
            eprintln!("database migrations applied");
        }
        "create-user" if args.len() == 2 => {
            db::migrate(&pool).await?;
            println!("{}", db::issue_token(&pool, &args[1], true, false).await?);
        }
        "create-token" if args.len() == 2 || (args.len() == 3 && args[2] == "--read-only") => {
            db::migrate(&pool).await?;
            println!("{}", db::issue_token(&pool, &args[1], false, args.len() == 3).await?);
        }
        "revoke-token" if args.len() == 2 => {
            let id: uuid::Uuid = args[1].parse().context("invalid token UUID")?;
            let changed = pool.get().await?.execute("UPDATE tokens SET revoked=true WHERE id=$1", &[&id]).await?;
            if changed != 1 {
                bail!("token not found");
            }
            eprintln!("token revoked");
        }
        "inspect-recovery" if args.len() == 2 => {
            db::migrate(&pool).await?;
            println!("{}", rootyard::maintenance::inspect(&config, &pool, args[1].parse()?).await?);
        }
        "resolve-unknown"
            if args.len() == 8
                && args[2] == "--expected-generation"
                && args[4] == "--fingerprint"
                && args[6] == "--acknowledge-audit-gap" =>
        {
            db::migrate(&pool).await?;
            println!(
                "{}",
                rootyard::maintenance::resolve(&config, &pool, args[1].parse()?, args[3].parse()?, &args[5], &args[7])
                    .await?
            );
        }
        "pando-transition" if args.len() >= 2 => {
            rootyard::pando_gateway::transition::operator::cli(&config, &pool, &args[1..]).await?;
        }
        "reconcile" if args.len() == 1 => {
            db::migrate(&pool).await?;
            let storage = Storage::open(&config)?;
            let hooks = rootyard::reliability::install_hooks(&storage.root)?;
            let state = AppState {
                mirror_primary: None,
                git_slots: Arc::new(tokio::sync::Semaphore::new(config.max_concurrent_git)),
                config,
                pool,
                storage,
                hooks: Some(hooks),
                transfer_metrics: Arc::new(rootyard::metrics::TransferCounters::default()),
                dispatch: rootyard::dispatch::Signals::default(),
            };
            rootyard::reliability::recover_startup(&state).await?;
            rootyard::sharding::transitions::reconcile_pending(&state).await.map_err(|e| anyhow::anyhow!(e.1))?;
            println!("offline reconciliation finished; inspect repository states for unresolved incidents");
        }
        "serve-mirror" if args.len() == 1 => {
            let state = rootyard::mirror::open(config, pool).await?;
            let listener = tokio::net::TcpListener::bind(state.config.bind).await?;
            eprintln!("rootyard read mirror listening on {}", listener.local_addr()?);
            axum::serve(listener, rootyard::mirror::router(state)).with_graceful_shutdown(shutdown()).await?;
        }
        "serve" if args.len() <= 1 => {
            let dispatch_settings = rootyard::dispatch::Settings::from_env()?;
            let maintenance_policy = rootyard::storage_lifecycle::models::Policy::from_env()?;
            std::fs::read_to_string("/proc/self/stat")
                .context("readable Linux procfs is required for writer cleanup")?;
            let storage = Storage::open(&config)?;
            let version = storage.git(&config).arg("--version").output().await?;
            let text = String::from_utf8(version.stdout)?;
            let numbers: Vec<_> = text
                .split_whitespace()
                .nth(2)
                .unwrap_or("")
                .split('.')
                .take(2)
                .map(|n| n.parse::<u32>().unwrap_or(0))
                .collect();
            if !version.status.success() || numbers.len() != 2 || (numbers[0], numbers[1]) < (2, 43) {
                bail!("Git 2.43 or newer is required");
            }
            db::prepare_runtime_schema(&pool).await?;
            // A restore can install its guard while this server waits for the
            // migration advisory lock; recheck before any recovery or serving.
            rootyard::backup::ensure_not_restoring(&storage.root)?;
            let slots = Arc::new(tokio::sync::Semaphore::new(config.max_concurrent_git));
            let hooks = rootyard::reliability::install_hooks(&storage.root)?;
            let state = Arc::new(AppState {
                mirror_primary: None,
                config,
                pool,
                storage,
                hooks: Some(hooks),
                transfer_metrics: Arc::new(rootyard::metrics::TransferCounters::default()),
                dispatch: rootyard::dispatch::Signals::default(),
                git_slots: slots,
            });
            let configured_node = std::env::var("ROOTYARD_NODE_ID").ok();
            let local_fence = if std::env::var_os("ROOTYARD_LOCAL_FENCE_DIR").is_some() {
                let node_id = configured_node.as_deref().context("local process fence requires ROOTYARD_NODE_ID")?;
                rootyard::sharding::local_fence::register_local_process(node_id)?;
                rootyard::sharding::local_fence::register_local_volume(
                    node_id,
                    &state.storage.root,
                    state.storage.volume_id,
                )?;
                true
            } else {
                false
            };
            rootyard::reliability::recover_startup(&state).await?;
            rootyard::sharding::transitions::reconcile_pending(&state).await.map_err(|e| anyhow::anyhow!(e.1))?;
            rootyard::recover(&state).await?;
            rootyard::sandbox::reconcile_startup(&state)
                .await
                .map_err(|_| anyhow::anyhow!("sandbox startup recovery failed"))?;
            rootyard::workspaces::mounts::reconcile_startup(&state)
                .await
                .map_err(|_| anyhow::anyhow!("workspace FUSE mount recovery failed"))?;
            let listener = tokio::net::TcpListener::bind(state.config.bind).await?;
            // Lease renewal is independent of the single-host fencing driver;
            // takeover scanning still requires a verifiable physical fence.
            let controller_task = if configured_node.is_some() || local_fence {
                Some(tokio::spawn(rootyard::sharding::controller::run(state.clone())))
            } else {
                None
            };
            eprintln!("rootyard listening on {} (GitFS single-node)", listener.local_addr()?);
            let metrics_worker = if let Some(address) = state.config.metrics_bind {
                let listener = tokio::net::TcpListener::bind(rootyard::metrics::validate_bind(address)?).await?;
                let router = rootyard::metrics::router(
                    state.pool.clone(),
                    state.git_slots.clone(),
                    state.config.max_concurrent_git,
                    state.transfer_metrics.clone(),
                );
                Some(tokio::spawn(async move {
                    if axum::serve(listener, router).await.is_err() {
                        eprintln!("rootyard: metrics listener stopped");
                    }
                }))
            } else {
                None
            };
            let dispatch_stop = tokio_util::sync::CancellationToken::new();
            let publish_task = tokio::spawn(rootyard::dispatch::publisher(
                dispatch_settings.transport.clone(),
                state.dispatch.remote.clone(),
                dispatch_stop.clone(),
            ));
            let delivery_task = if state.config.outbox_worker {
                Some(tokio::spawn(rootyard::dispatch::worker(
                    state.pool.clone(),
                    dispatch_settings,
                    state.dispatch.local.clone(),
                    dispatch_stop.clone(),
                )))
            } else {
                None
            };
            let webhook_task = if state.config.outbox_worker {
                Some(tokio::spawn(rootyard::webhooks::background::worker(state.clone(), dispatch_stop.clone())))
            } else {
                None
            };
            let worker_state = state.clone();
            let workspace_capture_stop = tokio_util::sync::CancellationToken::new();
            let workspace_capture_task =
                tokio::spawn(rootyard::workspaces::capture::run(state.clone(), workspace_capture_stop.clone()));
            let worker = tokio::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
                loop {
                    interval.tick().await;
                    if rootyard::sharding::transitions::reconcile_pending(&worker_state).await.is_err() {
                        eprintln!("rootyard: shard marker reconciliation unavailable; affected writes remain fenced");
                    }
                    if rootyard::reliability::recover_pending(&worker_state).await.is_err() {
                        eprintln!("rootyard: journal retry unavailable");
                    }
                    if rootyard::recover(&worker_state).await.is_err() {
                        eprintln!("rootyard: provisioning retry unavailable");
                    }
                }
            });
            let maintenance_stop = tokio_util::sync::CancellationToken::new();
            let maintenance_task = maintenance_policy
                .enabled
                .then(|| tokio::spawn(rootyard::storage_lifecycle::run(state.clone(), maintenance_stop.clone())));
            axum::serve(listener, rootyard::router(state)).with_graceful_shutdown(shutdown()).await?;
            worker.abort();
            maintenance_stop.cancel();
            workspace_capture_stop.cancel();
            let _ = workspace_capture_task.await;
            if let Some(task) = controller_task {
                task.abort();
            }
            if let Some(task) = maintenance_task {
                task.await??;
            }
            dispatch_stop.cancel();
            let _ = publish_task.await;
            if let Some(task) = delivery_task {
                let _ = task.await;
            }
            if let Some(task) = webhook_task {
                let _ = task.await;
            }
            if let Some(metrics_worker) = metrics_worker {
                metrics_worker.abort();
            }
        }
        _ => bail!(
            "usage: rootyard [serve | serve-mirror | migrate | create-user NAME | create-token NAME [--read-only] | revoke-token UUID | worker | worker-once | reconcile | inspect-recovery UUID | resolve-unknown UUID --expected-generation N --fingerprint SHA256 --acknowledge-audit-gap REASON | pando-transition status|cutover|rollback --repository UUID | pando-transition recover-abandoned-draining --repository UUID --expected-transition UUID --expected-epoch N --expected-backend gitfs|pando --expected-generation N | backup PATH --offline | backup-verify PATH | restore PATH --isolated --trust-backup [--allow-legacy-schema007 | --allow-legacy-schema130]]"
        ),
    }
    Ok(())
}
async fn shutdown() {
    let mut term =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("install SIGTERM handler");
    tokio::select! {_=tokio::signal::ctrl_c()=>{},_=term.recv()=>{}}
}
