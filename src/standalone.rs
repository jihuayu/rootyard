//! Minimal serving lifecycle, with independent HTTP draining and worker stop.
//! Storage adapters construct routes; this path opens no GitFS volume. Its
//! default is local Notify + an embedded PostgreSQL target-audit consumer. An
//! explicit mode may remove that consumer for a separately supervised A4
//! worker, and an explicit A4 variable may attach the advisory Redis publisher
//! without changing the committed response. Browser sign-in is enabled on the
//! standalone service, so the shared bounded browser-session GC loop runs here
//! under its own token.
use anyhow::{Result, anyhow};
use axum::response::IntoResponse;
use deadpool_postgres::Pool;
use std::{future::IntoFuture, net::SocketAddr, sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;
mod config;
pub(crate) mod session_keyring;

/// Explicit integration entry while business endpoint equivalence is completed.
pub async fn run_from_env() -> Result<()> {
    let database_url = std::env::var("DATABASE_URL").map_err(|_| anyhow!("DATABASE_URL is required"))?;
    if let Ok(root) = std::env::var("ROOTYARD_DATA_DIR") {
        crate::backup::ensure_not_restoring(std::path::Path::new(&root))
            .map_err(|_| anyhow!("incomplete restore guard blocks Blob service startup"))?;
    }
    let pool = crate::db::pool(&database_url).map_err(|_| anyhow!("invalid PostgreSQL configuration"))?;
    let mut barrier_client = crate::db::connect_url(&database_url)
        .await
        .map_err(|_| anyhow!("could not open the lifecycle barrier session"))?;
    tokio::time::timeout(
        Duration::from_secs(5),
        barrier_client.batch_execute("SET application_name='rootyard-blob-barrier'"),
    )
    .await
    .map_err(|_| anyhow!("lifecycle barrier session setup timed out"))??;
    let barrier = crate::backup::prepare_serving_database(
        &pool,
        &mut barrier_client,
        tokio::time::Instant::now() + Duration::from_secs(30),
    )
    .await
    .map_err(startup_barrier_error)?;
    let _guard = crate::maintenance::paired_raft_backup::install_production_serving_guard(&barrier_client)
        .await
        .map_err(|e| startup_barrier_error(anyhow!("{e}")))?;
    let store = crate::blob_store::opendal::BlobStore::open(
        crate::blob_store::config::BlobProfile::from_env().map_err(|_| anyhow!("invalid Blob profile"))?,
    )
    .map_err(|_| anyhow!("could not construct remote Blob provider"))?;
    let (bind, gateway, sessions) = config::gateway_config(pool.clone(), store)?;
    let mut state = crate::blob_git_gateway::BlobGitState::new(gateway)
        .map_err(|_| anyhow!("invalid Blob Git gateway configuration"))?;
    // The standalone target uses the existing bounded in-process Memory profile
    // only. No Redis client/runtime is constructed and no environment-selected
    // backend is added here.
    let cache =
        crate::cache_wake::ServingCache::standalone_memory().map_err(|_| anyhow!("invalid cache configuration"))?;
    state = state.with_cache(Arc::new(cache));
    // One advisory signal set for this process. The local permit wakes the
    // embedded PG target-audit worker; the remote permit is consumed only by
    // the explicit opt-in publisher. It carries no event payload and never
    // affects the committed response.
    let dispatch = crate::dispatch::Signals::default();
    state = state.with_dispatch(dispatch.clone());
    if let Some(sessions) = sessions {
        state = state.with_sessions(sessions);
    }
    let router = crate::blob_git_gateway::router(Arc::new(state));
    let check = async {
        loop {
            if let Err(error) = barrier.ensure_held(&barrier_client).await {
                break error;
            }
            if let Err(error) =
                crate::maintenance::paired_raft_backup::ensure_serving_database_unfrozen(&barrier_client).await
            {
                break error;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    };
    let res = serve(router, pool, bind, check, dispatch).await;
    crate::maintenance::paired_raft_backup::shutdown_installed_peer_attestation_daemon();
    res
}

/// Only the typed lifecycle-barrier refusal keeps its fixed cause; a busy
/// barrier is not a startup failure. Every other error keeps the generic
/// startup message with nothing of its (possibly sensitive) text passed on.
pub(crate) fn startup_barrier_error(error: anyhow::Error) -> anyhow::Error {
    if error.downcast_ref::<crate::backup::BarrierBusy>().is_some() {
        return error.context("Blob service schema or lifecycle barrier is unavailable");
    }
    anyhow!("Blob service schema or lifecycle barrier is unavailable")
}

async fn serve(
    router: axum::Router,
    pool: Pool,
    bind: SocketAddr,
    check: impl std::future::Future<Output = anyhow::Error>,
    dispatch: crate::dispatch::Signals,
) -> Result<()> {
    // The default remains local Notify + embedded PG scan. External placement
    // is explicit and removes this process's A4 consumer entirely; the publisher
    // remains optional and independent of the external worker's PG ticker.
    let mode = crate::dispatch::a4_worker_mode_from_env().map_err(|_| anyhow!("invalid A4 worker mode"))?;
    let settings = crate::dispatch::Settings::standalone_from_env()
        .map_err(|_| anyhow!("invalid A4 advisory wake configuration"))?;
    let transport = settings.transport.clone();
    let wake = dispatch.local.clone();
    let remote = dispatch.remote.clone();
    let hard_stop = CancellationToken::new();
    let request_stop = hard_stop.clone();
    let router = router.layer(axum::middleware::from_fn(
        move |request: axum::extract::Request, next: axum::middleware::Next| {
            let request_stop = request_stop.clone();
            async move {
                tokio::select! {
                    biased;
                    _ = request_stop.cancelled() => (axum::http::StatusCode::SERVICE_UNAVAILABLE,
                        axum::Json(serde_json::json!({"error":"service temporarily unavailable"}))).into_response(),
                    response = next.run(request) => response,
                }
            }
        },
    ));
    let listener =
        tokio::net::TcpListener::bind(bind).await.map_err(|_| anyhow!("could not bind Blob service listener"))?;
    let dispatch_stop = CancellationToken::new();
    let server_stop = CancellationToken::new();
    let mut worker = if mode.runs_embedded_worker() {
        Some(tokio::spawn(crate::dispatch::worker(pool.clone(), settings, wake, dispatch_stop.clone())))
    } else {
        // No dormant local consumer: the independent A4 worker owns every
        // target-audit claim and keeps its own mandatory PG ticker.
        None
    };
    // A publish failure or a lost hint only delays the existing PG poll. The
    // committed response above already completed; this task never owns a
    // terminal, outbox row or retry decision. It shares the one dispatch stop
    // token so shutdown cancels subscription-free publishes promptly.
    let mut publisher = tokio::spawn(crate::dispatch::publisher(transport, remote, dispatch_stop.clone()));
    // The one shared browser-session GC loop. It needs only PostgreSQL and is
    // stopped and awaited on every exit path below.
    let session_gc_stop = CancellationToken::new();
    let mut session_gc = tokio::spawn(crate::web::session_gc::run(pool, session_gc_stop.clone()));
    let serving =
        axum::serve(listener, router).with_graceful_shutdown(server_stop.clone().cancelled_owned()).into_future();
    tokio::pin!(serving);
    enum Stop {
        Listener(Result<(), std::io::Error>),
        Worker,
        Signal,
        Barrier(anyhow::Error),
    }
    let reason = {
        // The optional worker future is pending forever in external placement,
        // so the listener, signal and barrier remain the only stop sources there.
        let worker_exit = async {
            match worker.as_mut() {
                Some(worker) => {
                    let _ = worker.await;
                }
                None => std::future::pending::<()>().await,
            }
        };
        tokio::pin!(worker_exit);
        tokio::select! {
            result = &mut serving => Stop::Listener(result),
            _ = &mut worker_exit => Stop::Worker,
            _ = shutdown() => Stop::Signal,
            error = check => Stop::Barrier(error),
        }
    };
    // A worker panic and a normal worker exit both close admission first, then
    // drain active HTTP work. Neither path exposes a panic payload or drops
    // the server before signaling graceful shutdown.
    server_stop.cancel();
    dispatch_stop.cancel();
    let worker_failed = matches!(&reason, Stop::Worker);
    let result = match reason {
        Stop::Listener(result) => result.map_err(|_| anyhow!("Blob service listener failed")),
        Stop::Barrier(error) => {
            hard_stop.cancel();
            let _ = tokio::time::timeout(Duration::from_secs(5), &mut serving).await;
            Err(error.context("Blob service lost its lifecycle barrier"))
        }
        Stop::Worker | Stop::Signal => match tokio::time::timeout(Duration::from_secs(120), &mut serving).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(anyhow!("Blob service listener failed during drain")),
            Err(_) => Err(anyhow!("Blob service drain deadline exceeded")),
        },
    };
    // Cancel and bounded-await the one GC task on every exit path, including a
    // refused configuration (where it has already returned).
    session_gc_stop.cancel();
    if !session_gc.is_finished() {
        match tokio::time::timeout(Duration::from_secs(5), &mut session_gc).await {
            Ok(_) => {}
            Err(_) => {
                session_gc.abort();
                let _ = session_gc.await;
            }
        }
    }
    if let Some(worker) = worker.as_mut()
        && !worker.is_finished()
    {
        match tokio::time::timeout(Duration::from_secs(5), &mut *worker).await {
            Ok(_) => {}
            Err(_) => {
                worker.abort();
                let _ = worker.await;
            }
        }
    }
    if !publisher.is_finished() {
        match tokio::time::timeout(Duration::from_secs(5), &mut publisher).await {
            Ok(_) => {}
            Err(_) => {
                publisher.abort();
                let _ = publisher.await;
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
