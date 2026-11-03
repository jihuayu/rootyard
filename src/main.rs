use anyhow::{Context, Result, bail};
use rootyard::{AppState, config::Config, db, storage::Storage};
use std::sync::Arc;

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() == 2 && args[1] == "--rootyard-hook-self-check" {
        println!("rootyard-hook-v1");
        return Ok(());
    }
    let name = std::path::Path::new(&args[0])
        .file_name()
        .and_then(|v| v.to_str())
        .unwrap_or("");
    match name {
        "reference-transaction" => {
            return rootyard::journal::run_hook(args.get(1).map(String::as_str).unwrap_or(""));
        }
        "post-receive" => return rootyard::journal::run_post_receive(),
        "pre-receive" => return rootyard::journal::run_pre_receive(),
        _ => {}
    }
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run())
}
async fn run() -> Result<()> {
    if !cfg!(target_os = "linux") {
        bail!("Rootyard phase one currently supports Linux only");
    }
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.first().is_some_and(|s| s == "backup-verify") && args.len() == 2 {
        return rootyard::backup::check(std::path::Path::new(&args[1])).map_err(|_| {
            anyhow::anyhow!("backup verification failed; incomplete, unsafe or mismatched files")
        });
    }
    let config = Config::from_env()?;
    let pool = db::pool(&config.database_url)?;
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str).unwrap_or("serve") {
        "backup" if args.len() == 3 && args[2] == "--offline" => {
            rootyard::backup::create(&config, std::path::Path::new(&args[1])).await
                .map_err(|_| anyhow::anyhow!("backup failed; requires stopped writers, supported dedicated database and safe new destination; partial files may remain"))?;
        }
        "restore" if args.len() == 4 && args[2] == "--isolated" && args[3] == "--trust-backup" => {
            rootyard::backup::restore(&config, std::path::Path::new(&args[1])).await
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
            println!(
                "{}",
                db::issue_token(&pool, &args[1], false, args.len() == 3).await?
            );
        }
        "revoke-token" if args.len() == 2 => {
            let id: uuid::Uuid = args[1].parse().context("invalid token UUID")?;
            let changed = pool
                .get()
                .await?
                .execute("UPDATE tokens SET revoked=true WHERE id=$1", &[&id])
                .await?;
            if changed != 1 {
                bail!("token not found");
            }
            eprintln!("token revoked");
        }
        "inspect-recovery" if args.len() == 2 => {
            db::migrate(&pool).await?;
            println!(
                "{}",
                rootyard::maintenance::inspect(&config, &pool, args[1].parse()?).await?
            );
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
                rootyard::maintenance::resolve(
                    &config,
                    &pool,
                    args[1].parse()?,
                    args[3].parse()?,
                    &args[5],
                    &args[7]
                )
                .await?
            );
        }
        "reconcile" if args.len() == 1 => {
            db::migrate(&pool).await?;
            let storage = Storage::open(&config)?;
            let hooks = rootyard::reliability::install_hooks(&storage.root)?;
            let state = AppState {
                git_slots: Arc::new(tokio::sync::Semaphore::new(config.max_concurrent_git)),
                config,
                pool,
                storage,
                hooks,
                transfer_metrics: Arc::new(rootyard::metrics::TransferCounters::default()),
            };
            rootyard::reliability::recover_startup(&state).await?;
            println!(
                "offline reconciliation finished; inspect repository states for unresolved incidents"
            );
        }
        "worker-once" if args.len() == 1 => {
            db::migrate(&pool).await?;
            let owner = uuid::Uuid::new_v4();
            let mut count = 0;
            for consumer in ["audit-log", "ref-index"] {
                count += rootyard::events::worker_once(&pool, consumer, owner, 64).await?;
            }
            println!("{count}");
        }
        "serve" if args.len() <= 1 => {
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
            if !version.status.success() || numbers.len() != 2 || (numbers[0], numbers[1]) < (2, 43)
            {
                bail!("Git 2.43 or newer is required");
            }
            db::migrate(&pool).await?;
            // A restore can install its guard while this server waits for the
            // migration advisory lock; recheck before any recovery or serving.
            rootyard::backup::ensure_not_restoring(&storage.root)?;
            let slots = Arc::new(tokio::sync::Semaphore::new(config.max_concurrent_git));
            let hooks = rootyard::reliability::install_hooks(&storage.root)?;
            let state = Arc::new(AppState {
                config,
                pool,
                storage,
                hooks,
                transfer_metrics: Arc::new(rootyard::metrics::TransferCounters::default()),
                git_slots: slots,
            });
            rootyard::reliability::recover_startup(&state).await?;
            rootyard::recover(&state).await?;
            let listener = tokio::net::TcpListener::bind(state.config.bind).await?;
            eprintln!(
                "rootyard listening on {} (GitFS single-node)",
                listener.local_addr()?
            );
            let metrics_worker = if let Some(address) = state.config.metrics_bind {
                let listener =
                    tokio::net::TcpListener::bind(rootyard::metrics::validate_bind(address)?)
                        .await?;
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
            let worker_state = state.clone();
            let worker = tokio::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
                loop {
                    interval.tick().await;
                    if rootyard::reliability::recover_pending(&worker_state)
                        .await
                        .is_err()
                    {
                        eprintln!("rootyard: journal retry unavailable");
                    }
                    if worker_state.config.outbox_worker
                        && rootyard::reliability::worker_once(&worker_state)
                            .await
                            .is_err()
                    {
                        eprintln!("rootyard: durable worker retry unavailable");
                    }
                    if rootyard::recover(&worker_state).await.is_err() {
                        eprintln!("rootyard: provisioning retry unavailable");
                    }
                }
            });
            axum::serve(listener, rootyard::router(state))
                .with_graceful_shutdown(shutdown())
                .await?;
            worker.abort();
            if let Some(metrics_worker) = metrics_worker {
                metrics_worker.abort();
            }
        }
        _ => bail!(
            "usage: rootyard [serve | migrate | create-user NAME | create-token NAME [--read-only] | revoke-token UUID | worker-once | reconcile | inspect-recovery UUID | resolve-unknown UUID --expected-generation N --fingerprint SHA256 --acknowledge-audit-gap REASON | backup PATH --offline | backup-verify PATH | restore PATH --isolated --trust-backup]"
        ),
    }
    Ok(())
}
async fn shutdown() {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("install SIGTERM handler");
    tokio::select! {_=tokio::signal::ctrl_c()=>{},_=term.recv()=>{}}
}
