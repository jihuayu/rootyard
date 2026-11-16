use anyhow::{Context, Result, bail};
use rootyard::{AppState, config::Config, db, storage::Storage};
use std::sync::Arc;

mod service_shutdown;

/// Ordinary CLI success or the service branch's bounded cleanup outcome. Only
/// the service branch may request a bounded runtime shutdown on an
/// unsuccessful/pending teardown; ordinary CLI behavior keeps the normal drop.
enum RunOutcome {
    Ordinary,
    Service(service_shutdown::ServiceCompletion),
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() == 2 && args[1] == "--rootyard-hook-self-check" {
        println!("rootyard-hook-v1");
        return Ok(());
    }
    if args.len() == 2 && args[1] == rootyard::workspace_lab::fuse_helper::HELPER_ARG {
        // The independent workspace FUSE helper branches before Config, the DB
        // pool, `Store` and the volume lock exist: the child must never open
        // PostgreSQL, the API router or the service storage lock. It receives
        // only the two inherited sockets and a scrubbed environment.
        if !cfg!(target_os = "linux") {
            bail!("workspace FUSE helper requires Linux");
        }
        return rootyard::workspace_lab::fuse_helper::run_child().context("workspace FUSE helper stopped");
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
    // The top-level runtime is explicit so an unsuccessful service cleanup can
    // consume only the remaining product deadline through `shutdown_timeout`.
    // That bounded wait is terminal failure containment, never proof of native
    // cleanup, and it is not used on an ordinary/clean path.
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    let outcome = runtime.block_on(run());
    match outcome {
        Ok(RunOutcome::Ordinary) => {
            drop(runtime);
            Ok(())
        }
        Ok(RunOutcome::Service(completion)) => {
            let pending = completion.pending_runtime();
            let remaining = completion.remaining();
            if pending {
                // Keep the completion (and any retained startup owner) alive
                // through bounded runtime termination. The timeout is failure
                // containment; it never proves cleanup.
                runtime.shutdown_timeout(remaining);
                completion.into_result()
            } else {
                drop(runtime);
                completion.into_result()
            }
        }
        Err(error) => {
            drop(runtime);
            Err(error)
        }
    }
}
async fn run() -> Result<RunOutcome> {
    if !cfg!(target_os = "linux") {
        bail!("Rootyard phase one currently supports Linux only");
    }
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() == 1 && args[0] == "serve-blob" {
        return rootyard::standalone::run_from_env().await.map(|()| RunOutcome::Ordinary);
    }
    if args.first().is_some_and(|s| s == "backup-verify") && args.len() == 2 {
        return rootyard::backup::check(std::path::Path::new(&args[1]))
            .map(|()| RunOutcome::Ordinary)
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
            // Browser-session GC needs only PostgreSQL, so the control-plane
            // worker runs the same bounded loop as the serving process.
            let session_gc_task = tokio::spawn(rootyard::web::session_gc::run(pool.clone(), stop.child_token()));
            let mut task = tokio::spawn(rootyard::dispatch::worker(
                pool,
                settings,
                Arc::new(tokio::sync::Notify::new()),
                stop.clone(),
            ));
            eprintln!("rootyard: PostgreSQL delivery worker started (no Git storage access)");
            tokio::select! {
                _=shutdown()=>{ stop.cancel(); task.await?; let _ = session_gc_task.await; },
                result=&mut task=>{ result?; bail!("delivery worker stopped unexpectedly"); },
            }
        }
        return Ok(RunOutcome::Ordinary);
    }
    let config = Config::from_env()?;
    let pool = db::pool(&config.database_url)?;
    match args.first().map(String::as_str).unwrap_or("serve") {
        "backup" if args.len() == 3 && args[2] == "--offline" => {
            rootyard::backup::create(&config, std::path::Path::new(&args[1])).await.map_err(backup_refusal)?;
        }
        "restore"
            if (args.len() == 4
                || (args.len() == 5
                    && matches!(
                        args[4].as_str(),
                        "--allow-legacy-schema007"
                            | "--allow-legacy-schema130"
                            | "--allow-legacy-schema131"
                            | "--allow-legacy-schema132"
                            | "--allow-legacy-schema133"
                            | "--allow-legacy-schema134"
                            | "--allow-legacy-schema135"
                            | "--allow-legacy-schema136"
                            | "--allow-legacy-schema137"
                            | "--allow-legacy-schema138"
                            | "--allow-legacy-schema139"
                            | "--allow-legacy-schema140"
                            | "--allow-legacy-schema141"
                            | "--allow-legacy-schema142"
                            | "--allow-legacy-schema143"
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
                legacy == Some("--allow-legacy-schema132"),
                legacy == Some("--allow-legacy-schema133"),
                legacy == Some("--allow-legacy-schema134"),
                legacy == Some("--allow-legacy-schema135"),
                legacy == Some("--allow-legacy-schema136"),
                legacy == Some("--allow-legacy-schema137"),
                legacy == Some("--allow-legacy-schema138"),
                legacy == Some("--allow-legacy-schema139"),
                legacy == Some("--allow-legacy-schema140"),
                legacy == Some("--allow-legacy-schema141"),
                legacy == Some("--allow-legacy-schema142"),
                legacy == Some("--allow-legacy-schema143"),
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
        "pando-authority" if args.len() >= 2 => {
            rootyard::pando_gateway::authority_cli::cli(&config, &pool, &args[1..]).await?;
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
            rootyard::sharding::sidecar::reconcile_startup(&state).await.map_err(|e| anyhow::anyhow!(e.1))?;
            println!("offline reconciliation finished; inspect repository states for unresolved incidents");
        }
        "serve-mirror" if args.len() == 1 => {
            let state = rootyard::mirror::open(config, pool).await?;
            let listener = tokio::net::TcpListener::bind(state.config.bind).await?;
            eprintln!("rootyard read mirror listening on {}", listener.local_addr()?);
            axum::serve(listener, rootyard::mirror::router(state)).with_graceful_shutdown(shutdown()).await?;
        }
        "serve" if args.len() <= 1 => {
            rootyard::config::init_workspace_remote_delete_policy()?;
            rootyard::storage_lifecycle::pando_delete_gate::validate_startup_env()?;
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
            // Fail startup on invalid admission settings before the listener
            // accepts authentication traffic.
            rootyard::auth_admission::init_for_state(&state)?;
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
            rootyard::sharding::sidecar::reconcile_startup(&state).await.map_err(|e| anyhow::anyhow!(e.1))?;
            rootyard::recover(&state).await?;
            rootyard::sandbox::reconcile_startup(&state)
                .await
                .map_err(|_| anyhow::anyhow!("sandbox startup recovery failed"))?;
            // Arm the one service-lifecycle owner before reconcile. Every
            // fallible post-mount step below runs inside this result-producing
            // scope, so a later failure never bypasses cleanup.
            let git_shutdown_grace = std::time::Duration::from_secs(30).saturating_add(state.config.git_timeout);
            let mut lifecycle = service_shutdown::ServiceOwner::arm(git_shutdown_grace);
            // Register both Unix stop streams synchronously before the first
            // legacy mount can be admitted. The owner is already armed, so a
            // registration failure still enters the same cleanup funnel.
            let mut signals = match service_shutdown::StopSignals::install() {
                Ok(signals) => signals,
                Err(error) => {
                    let completion = lifecycle.cleanup(Some(error), &service_shutdown::NativeCleanupDriver).await;
                    return Ok(RunOutcome::Service(completion));
                }
            };
            let startup = rootyard::workspaces::mounts::StartupReconcile::prepare(state.clone());
            lifecycle.attach_startup(startup);
            let setup = async {
                match lifecycle.wait_startup().await {
                    Ok(rootyard::workspaces::mounts::StartupOutcome::Completed(Ok(()))) => {}
                    Ok(rootyard::workspaces::mounts::StartupOutcome::Completed(Err(error))) => {
                        return Err(anyhow::Error::new(error));
                    }
                    Ok(rootyard::workspaces::mounts::StartupOutcome::Stopped) => {
                        return Err(service_shutdown::startup_stopped());
                    }
                    Err(error) => return Err(service_shutdown::startup_join_failure(error)),
                }
                rootyard::pando_gateway::pitr_fence::startup_check(&state.pool, &state.storage.root).await?;
                let listener = tokio::net::TcpListener::bind(state.config.bind).await?;
                // Lease renewal is independent of the single-host fencing
                // driver; takeover scanning still requires a verifiable
                // physical fence.
                let controller_task = if configured_node.is_some() || local_fence {
                    Some(tokio::spawn(rootyard::sharding::controller::run(state.clone())))
                } else {
                    None
                };
                if let Some(task) = controller_task {
                    lifecycle.attach_controller(task);
                }
                eprintln!("rootyard listening on {} (GitFS single-node)", listener.local_addr()?);
                let metrics_worker = if let Some(address) = state.config.metrics_bind {
                    let listener = tokio::net::TcpListener::bind(rootyard::metrics::validate_bind(address)?).await?;
                    let router = rootyard::metrics::router(
                        state.pool.clone(),
                        state.git_slots.clone(),
                        state.config.max_concurrent_git,
                        state.transfer_metrics.clone(),
                        rootyard::metrics_workers::Config {
                            volume_id: state.storage.volume_id,
                            scan_period_seconds: maintenance_policy.scan_period_seconds,
                        },
                    );
                    Some(tokio::spawn(async move {
                        if axum::serve(listener, router).await.is_err() {
                            eprintln!("rootyard: metrics listener stopped");
                        }
                    }))
                } else {
                    None
                };
                if let Some(task) = metrics_worker {
                    lifecycle.attach_metrics(task);
                }
                let dispatch_stop = lifecycle.dispatch_stop().clone();
                let publish_task = tokio::spawn(rootyard::dispatch::publisher(
                    dispatch_settings.transport.clone(),
                    state.dispatch.remote.clone(),
                    dispatch_stop.clone(),
                ));
                lifecycle.attach_publish(publish_task);
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
                if let Some(task) = delivery_task {
                    lifecycle.attach_delivery(task);
                }
                let webhook_task = if state.config.outbox_worker {
                    Some(tokio::spawn(rootyard::webhooks::background::worker(state.clone(), dispatch_stop.clone())))
                } else {
                    None
                };
                if let Some(task) = webhook_task {
                    lifecycle.attach_webhook(task);
                }
                let worker_state = state.clone();
                let workspace_capture_stop = lifecycle.capture_stop().clone();
                let workspace_capture_task =
                    tokio::spawn(rootyard::workspaces::capture::run(state.clone(), workspace_capture_stop));
                lifecycle.attach_capture(workspace_capture_task);
                let worker = tokio::spawn(async move {
                    let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
                    loop {
                        interval.tick().await;
                        if rootyard::sharding::transitions::reconcile_pending(&worker_state).await.is_err() {
                            eprintln!(
                                "rootyard: shard marker reconciliation unavailable; affected writes remain fenced"
                            );
                        }
                        if rootyard::reliability::recover_pending(&worker_state).await.is_err() {
                            eprintln!("rootyard: journal retry unavailable");
                        }
                        if rootyard::recover(&worker_state).await.is_err() {
                            eprintln!("rootyard: provisioning retry unavailable");
                        }
                    }
                });
                lifecycle.attach_worker(worker);
                let maintenance_stop = lifecycle.maintenance_stop().clone();
                let maintenance_task = maintenance_policy
                    .enabled
                    .then(|| tokio::spawn(rootyard::storage_lifecycle::run(state.clone(), maintenance_stop)));
                if let Some(task) = maintenance_task {
                    lifecycle.attach_maintenance(task);
                }
                let session_gc_stop = lifecycle.session_gc_stop().clone();
                let session_gc_task = tokio::spawn(rootyard::web::session_gc::run(state.pool.clone(), session_gc_stop));
                lifecycle.attach_session_gc(session_gc_task);
                // A disconnected client must not cancel a started workspace Git
                // mutation. Keep the serving future owned, but do not await its
                // in-flight requests before the helper has had a chance to
                // unmount and release a FUSE-parked Git child.
                let http_stop_for_server = lifecycle.http_stop().clone();
                let server = tokio::spawn(async move {
                    axum::serve(
                        listener,
                        rootyard::router(state).into_make_service_with_connect_info::<std::net::SocketAddr>(),
                    )
                    .with_graceful_shutdown(async move { http_stop_for_server.cancelled().await })
                    .await
                });
                lifecycle.attach_server(server);
                Ok(())
            };
            let mut setup = Box::pin(setup);
            let trigger = service_shutdown::select_startup(signals.next(), &mut setup).await;
            // Drop only the setup wrapper. The owned startup producer remains
            // in the lifecycle owner and is joined concurrently with mount
            // teardown under the same deadline.
            drop(setup);
            let primary = match trigger {
                service_shutdown::StartupTrigger::Stop(Ok(())) => {
                    lifecycle.begin_stop();
                    None
                }
                service_shutdown::StartupTrigger::Stop(Err(error)) => {
                    lifecycle.begin_stop();
                    Some(error)
                }
                service_shutdown::StartupTrigger::Setup(Err(error)) => {
                    lifecycle.begin_stop();
                    if service_shutdown::is_startup_stopped(&error) { None } else { Some(error) }
                }
                service_shutdown::StartupTrigger::Setup(Ok(())) => {
                    lifecycle.wait_for_stop_or_serve(signals.next()).await
                }
            };
            let completion = lifecycle.cleanup(primary, &service_shutdown::NativeCleanupDriver).await;
            return Ok(RunOutcome::Service(completion));
        }
        _ => bail!(
            "usage: rootyard [serve | serve-blob | serve-mirror | migrate | create-user NAME | create-token NAME [--read-only] | revoke-token UUID | worker | worker-once | reconcile | inspect-recovery UUID | resolve-unknown UUID --expected-generation N --fingerprint SHA256 --acknowledge-audit-gap REASON | pando-transition status|cutover|rollback --repository UUID | pando-transition recover-abandoned-draining --repository UUID --expected-transition UUID --expected-epoch N --expected-backend gitfs|pando --expected-generation N | pando-authority status|verify|isolate --confirm-shared-bucket|pin-recovery-point|release-recovery-point | backup PATH --offline | backup-verify PATH | restore PATH --isolated --trust-backup [--allow-legacy-schema007 | --allow-legacy-schema130 | --allow-legacy-schema131 | --allow-legacy-schema132 | --allow-legacy-schema133 | --allow-legacy-schema134 | --allow-legacy-schema135 | --allow-legacy-schema136 | --allow-legacy-schema137 | --allow-legacy-schema138 | --allow-legacy-schema139 | --allow-legacy-schema140 | --allow-legacy-schema141 | --allow-legacy-schema142 | --allow-legacy-schema143]]"
        ),
    }
    Ok(RunOutcome::Ordinary)
}

/// The one generic backup refusal every other failure keeps byte-for-byte.
const BACKUP_REFUSAL: &str = "backup failed; requires stopped writers, supported dedicated database and safe new \
    destination; partial files may remain";
/// The source-validator refusal context, kept between the generic prefix and
/// the typed summary.
const LEDGER_CONTEXT: &str = "source artifact ledger cannot be archived";

/// The CLI backup diagnostic. Only a `LedgerValidationRefusal` cause (the
/// source validator ran every read and check and refused a non-empty violation
/// set) is named: the generic prefix plus its fixed count + summary-code
/// summary. Every other error keeps the generic message byte-for-byte, and no
/// arbitrary anyhow chain is ever printed.
fn backup_refusal(error: anyhow::Error) -> anyhow::Error {
    match ledger_refusal(&error) {
        Some(summary) => anyhow::anyhow!("{BACKUP_REFUSAL}: {LEDGER_CONTEXT}: {summary}"),
        None => anyhow::anyhow!("{BACKUP_REFUSAL}"),
    }
}

/// The summary of the one typed source-ledger cause in `error`'s chain, never
/// the cause's own text and never any chain text.
fn ledger_refusal(error: &anyhow::Error) -> Option<String> {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<rootyard::backup::LedgerValidationRefusal>())
        .map(rootyard::backup::LedgerValidationRefusal::diagnostic)
}

async fn shutdown() {
    let mut term =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("install SIGTERM handler");
    tokio::select! {_=tokio::signal::ctrl_c()=>{},_=term.recv()=>{}}
}
