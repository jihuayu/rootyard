use anyhow::{Context, Result, bail};
use rootyard::{AppState, config::Config, db, storage::Storage};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<()> {
    if !cfg!(target_os = "linux") {
        bail!("Rootyard phase one currently supports Linux only");
    }
    let config = Config::from_env()?;
    let pool = db::pool(&config.database_url)?;
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str).unwrap_or("serve") {
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
        "serve" if args.len() <= 1 => {
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
            let slots = Arc::new(tokio::sync::Semaphore::new(config.max_concurrent_git));
            let state = Arc::new(AppState {
                config,
                pool,
                storage,
                git_slots: slots,
            });
            rootyard::recover(&state).await?;
            let listener = tokio::net::TcpListener::bind(state.config.bind).await?;
            eprintln!(
                "rootyard listening on {} (GitFS single-node)",
                listener.local_addr()?
            );
            let worker_state = state.clone();
            let worker = tokio::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
                loop {
                    interval.tick().await;
                    if rootyard::recover(&worker_state).await.is_err() {
                        eprintln!("rootyard: provisioning retry unavailable");
                    }
                }
            });
            axum::serve(listener, rootyard::router(state))
                .with_graceful_shutdown(shutdown())
                .await?;
            worker.abort();
        }
        _ => bail!(
            "usage: rootyard [serve | migrate | create-user NAME | create-token NAME [--read-only] | revoke-token UUID]"
        ),
    }
    Ok(())
}
async fn shutdown() {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("install SIGTERM handler");
    tokio::select! {_=tokio::signal::ctrl_c()=>{},_=term.recv()=>{}}
}
