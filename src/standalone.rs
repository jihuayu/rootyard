//! Minimal serving lifecycle, with independent HTTP draining and worker stop.
//! Storage adapters construct routes; this path opens no GitFS volume or external wake.
use anyhow::{Result, anyhow};
use deadpool_postgres::Pool;
use std::{future::IntoFuture, net::SocketAddr, sync::Arc, time::Duration};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
mod config;

/// Explicit integration entry while business endpoint equivalence is completed.
pub async fn run_from_env() -> Result<()> {
    let database_url = std::env::var("DATABASE_URL").map_err(|_| anyhow!("DATABASE_URL is required"))?;
    let pool = crate::db::pool(&database_url).map_err(|_| anyhow!("invalid PostgreSQL configuration"))?;
    crate::db::prepare_runtime_schema(&pool).await.map_err(|_| anyhow!("Blob service schema unavailable"))?;
    let store = crate::blob_store::opendal::BlobStore::open(
        crate::blob_store::config::BlobProfile::from_env().map_err(|_| anyhow!("invalid Blob profile"))?,
    )
    .map_err(|_| anyhow!("could not construct remote Blob provider"))?;
    let (bind, gateway) = config::gateway_config(pool.clone(), store)?;
    let state = crate::blob_git_gateway::BlobGitState::new(gateway)
        .map_err(|_| anyhow!("invalid Blob Git gateway configuration"))?;
    let router = crate::blob_git_gateway::router(Arc::new(state));
    serve(router, pool, bind).await
}

pub async fn serve(router: axum::Router, pool: Pool, bind: SocketAddr) -> Result<()> {
    let listener =
        tokio::net::TcpListener::bind(bind).await.map_err(|_| anyhow!("could not bind Blob service listener"))?;
    let worker_stop = CancellationToken::new();
    let server_stop = CancellationToken::new();
    let mut worker = tokio::spawn(crate::dispatch::worker(
        pool,
        crate::dispatch::Settings::standalone(),
        Arc::new(Notify::new()),
        worker_stop.clone(),
    ));
    let serving =
        axum::serve(listener, router).with_graceful_shutdown(server_stop.clone().cancelled_owned()).into_future();
    tokio::pin!(serving);
    enum Stop {
        Listener(Result<(), std::io::Error>),
        Worker,
        Signal,
    }
    let reason = tokio::select! {
        result = &mut serving => Stop::Listener(result),
        _ = &mut worker => Stop::Worker,
        _ = shutdown() => Stop::Signal,
    };
    // A worker panic and a normal worker exit both close admission first, then
    // drain active HTTP work. Neither path exposes a panic payload or drops
    // the server before signaling graceful shutdown.
    server_stop.cancel();
    worker_stop.cancel();
    let worker_failed = matches!(&reason, Stop::Worker);
    let result = match reason {
        Stop::Listener(result) => result.map_err(|_| anyhow!("Blob service listener failed")),
        Stop::Worker | Stop::Signal => match tokio::time::timeout(Duration::from_secs(120), &mut serving).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(anyhow!("Blob service listener failed during drain")),
            Err(_) => Err(anyhow!("Blob service drain deadline exceeded")),
        },
    };
    if !worker.is_finished() {
        match tokio::time::timeout(Duration::from_secs(5), &mut worker).await {
            Ok(_) => {}
            Err(_) => {
                worker.abort();
                let _ = worker.await;
            }
        }
    }
    if worker_failed {
        return Err(anyhow!("durable worker stopped before shutdown"));
    }
    result
}

async fn shutdown() {
    #[cfg(unix)]
    {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
