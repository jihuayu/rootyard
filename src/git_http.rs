use crate::{
    AppState, Error, auth,
    db::{self, Identity, Repository},
    journal, reliability, storage,
};
use axum::{
    body::Body,
    http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode, header},
};
use bytes::Bytes;
use futures_util::StreamExt;
use std::{io, process::Stdio, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, BufReader},
    process::Child,
    sync::{OwnedMutexGuard, OwnedRwLockReadGuard, OwnedSemaphorePermit},
    task::JoinHandle,
    time::Instant,
};

#[path = "git_http/process.rs"]
mod process;
#[path = "git_http/protocol.rs"]
mod protocol;
use process::Process;
pub(crate) use process::{collect_git_output, collect_git_output_input,
    finish_group_child, stop_group_child};
use protocol::{job_response_prefix, receive_commands, route, validate_headers, read_headers};

async fn transfer_authorized(
    state: &AppState,
    identity: Option<&Identity>,
    job_plan: Option<&crate::ci_checkouts::Plan>,
    job_principal: Option<&crate::ci_checkouts::authority::CheckoutPrincipal>,
    repo: &Repository,
    write: bool,
) -> io::Result<()> {
    if let Some(plan) = job_plan {
        let digest = match job_principal {
            Some(crate::ci_checkouts::authority::CheckoutPrincipal::User(user)) => &user.token_digest,
            Some(crate::ci_checkouts::authority::CheckoutPrincipal::Integration { token_digest, .. }) => token_digest,
            None => return Err(io::Error::other("missing checkout principal")),
        };
        match crate::ci_checkouts::still_authorized(state, plan.job_id, digest,
            repo.id, repo.storage_generation).await {
            Ok(true) => Ok(()),
            _ => Err(io::Error::other("checkout authority revoked")),
        }
    } else {
        let user = identity.ok_or_else(|| io::Error::other("missing Git actor"))?;
        auth::verify_active(&state.pool, user, repo.id, write).await
            .map_err(|_| io::Error::other("Git authority revoked"))
    }
}

pub async fn handle(state: Arc<AppState>, request: Request<Body>) -> Result<Response<Body>, Error> {
    if let Some(plan) = crate::sharding::transport::route_git_request(&state, &request).await? {
        return crate::sharding::transport::forward_request(&state, plan, request).await;
    }
    // A disconnected caller cannot cancel cleanup between acquiring the write
    // lock and starting the response producer. The owned task retains all guards.
    tokio::spawn(execute(state, request))
        .await
        .map_err(Error::internal)?
}
async fn execute(state: Arc<AppState>, request: Request<Body>) -> Result<Response<Body>, Error> {
    let (parts, body) = request.into_parts();
    let (pin_oid, route_path) = if state.mirror_primary.is_some()
        || parts.uri.path().starts_with("/ci/") {
        let (oid, path) = crate::mirror::ci_route(parts.uri.path())?;
        (Some(oid), path)
    } else {
        (None, parts.uri.path())
    };
    let (owner, name, endpoint, service) = route(&parts.method, route_path, parts.uri.query())?;
    let write = service == "git-receive-pack";
    if write && pin_oid.is_some() {
        return Err(Error(
            StatusCode::FORBIDDEN,
            "read mirror never accepts pushes; use the primary",
        ));
    }
    let delegation = crate::sharding::transport::authenticate_delegation(
        &state, &parts.headers, &parts.method, &parts.uri,
    ).await?;
    let job = pin_oid.is_some() && auth::credentials_for(&parts.headers, "ryj_").is_ok();
    if pin_oid.is_some() && state.mirror_primary.is_none() && !job {
        return Err(Error::unauthorized());
    }
    let (identity, repo, job_plan, job_principal) = if let Some((identity, repo)) = delegation {
        (Some(identity), repo, None, None)
    } else if job {
        let (principal, repo, plan) = crate::ci_checkouts::authority::authenticate_principal(
            &state,
            &parts.headers,
            owner,
            name,
            pin_oid.unwrap(),
        )
        .await?;
        let identity = match &principal {
            crate::ci_checkouts::authority::CheckoutPrincipal::User(user) => Some(user.clone()),
            crate::ci_checkouts::authority::CheckoutPrincipal::Integration { .. } => None,
        };
        (identity, repo, Some(plan), Some(principal))
    } else {
        let identity = auth::authenticate(&state.pool, &parts.headers).await?;
        if write {
            auth::writable(&identity)?;
        }
        let row = state
            .pool
            .get()
            .await
            .map_err(Error::internal)?
            .query_opt(
                &format!("{} WHERE ns.slug=$1 AND r.name=$2", db::REPO_SELECT),
                &[&owner, &name],
            )
            .await
            .map_err(Error::internal)?
            .ok_or_else(Error::not_found)?;
        let repo = Repository::from_row(&row);
        let mut client = state.pool.get().await.map_err(Error::internal)?;
        let tx = client.transaction().await.map_err(Error::internal)?;
        auth::authorize_repo(&tx, &identity, owner, name, write).await.map_err(|error| {
            if error.0 == StatusCode::CONFLICT && error.1 == "repository is not ready" {
                Error(StatusCode::SERVICE_UNAVAILABLE, "repository not ready; recovery may be required")
            } else { error }
        })?;
        auth::finish_tx(tx, &identity, false).await?;
        if repo.state != "ready" {
            return Err(Error(
                StatusCode::SERVICE_UNAVAILABLE,
                "repository not ready; recovery may be required",
            ));
        }
        (Some(identity), repo, None, None)
    };
    let remote_user = match &job_principal {
        Some(crate::ci_checkouts::authority::CheckoutPrincipal::Integration { hook_id, job_id, .. }) =>
            format!("ci-job:{job_id}/integration:{hook_id}"),
        _ => identity.as_ref().ok_or_else(Error::unauthorized)?.username.clone(),
    };
    validate_headers(
        &parts.headers,
        &parts.method,
        service,
        state.config.max_request_bytes,
    )?;
    let permit = state.git_slots.clone().try_acquire_owned().map_err(|_| {
        Error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Git capacity exhausted; retry later",
        )
    })?;
    let deadline = Instant::now() + state.config.git_timeout;
    let gzipped = parts.headers.get(header::CONTENT_ENCODING)
        .is_some_and(|v| v == "gzip" || v == "x-gzip");
    let max_input = state.config.max_request_bytes;
    let input_metrics = state.transfer_metrics.clone();
    let mut wire_bytes = 0u64;
    let stream = body.into_data_stream().map(move |chunk| {
        let chunk = chunk.map_err(io::Error::other)?;
        wire_bytes = wire_bytes.saturating_add(chunk.len() as u64);
        input_metrics.add_received_bytes(chunk.len() as u64);
        if wire_bytes > max_input {
            return Err(io::Error::other("request wire size limit exceeded"));
        }
        Ok(chunk)
    });
    let reader = tokio_util::io::StreamReader::new(stream);
    let mut input_reader: std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send>> = if gzipped {
        let mut decoder = async_compression::tokio::bufread::GzipDecoder::new(BufReader::new(reader));
        decoder.multiple_members(true);
        Box::pin(decoder)
    } else { Box::pin(reader) };
    let receive = if write && parts.method == Method::POST {
        let oid_len = if repo.object_format == "sha256" { 64 } else { 40 };
        Some(tokio::time::timeout_at(deadline, receive_commands(&mut input_reader, oid_len))
            .await.map_err(|_| Error::timeout())??)
    } else { None };
    let ref_guard = if let Some(commands) = &receive {
        Some(storage::ref_publication::acquire(&state.pool, repo.id,
            repo.storage_generation, &commands.refs, deadline).await?)
    } else { None };
    let write_guard = if write && parts.method == Method::POST {
        Some(
            tokio::time::timeout_at(deadline, state.storage.write_lock(repo.id))
                .await
                .map_err(|_| Error::timeout())?,
        )
    } else {
        None
    };
    let snapshot_lease = if write_guard.is_none() {
        Some(storage::read_leases::shared(&state.pool, repo.id, deadline).await?)
    } else { None };
    let read_guard = if snapshot_lease.is_some() {
        Some(tokio::time::timeout_at(deadline, state.storage.read_snapshot_lock(repo.id))
            .await.map_err(|_| Error::timeout())?)
    } else { None };
    if snapshot_lease.is_some() {
        transfer_authorized(&state, identity.as_ref(), job_plan.as_ref(),
            job_principal.as_ref(), &repo, write).await.map_err(|_| Error::unauthorized())?;
    }
    if write_guard.is_some() {
        reliability::before_push(&state, &repo)
            .await
            .map_err(Error::internal)?;
    }
    let path = if let Some(oid) = pin_oid {
        if job {
            let plan = job_plan.as_ref().ok_or_else(Error::unauthorized)?;
            if state.mirror_primary.is_some() {
                crate::ci_checkouts::dependencies::verify_on_mirror(&state, plan).await?;
                crate::mirror::job_path(&state, &repo, plan).await?
            } else {
                let lease = snapshot_lease.as_ref().ok_or_else(Error::unauthorized)?;
                lease.guard(crate::ci_checkouts::origin_job_path(
                    &state, &repo, plan, lease)).await??
            }
        } else {
            crate::mirror::pinned_path(&state, &repo, oid).await?
        }
    } else {
        state
            .storage
            .verify_path(repo.id)
            .map_err(Error::internal)?
    };
    let project_root = path.parent().ok_or_else(Error::bad_request)?.to_path_buf();
    let repository_dir = path
        .file_name()
        .ok_or_else(Error::bad_request)?
        .to_string_lossy()
        .into_owned();
    if write_guard.is_some() {
        let quota = state.config.max_repo_bytes;
        let check_path = path.clone();
        let size = tokio::task::spawn_blocking(move || storage::disk_bytes(&check_path, quota))
            .await
            .map_err(Error::internal)?
            .map_err(Error::internal)?;
        if size >= quota {
            return Err(Error(
                StatusCode::INSUFFICIENT_STORAGE,
                "repository quota reached",
            ));
        }
    }
    let mut cmd = state.storage.git(&state.config);
    if job {
        cmd.env("GIT_NO_REPLACE_OBJECTS", "1");
    }
    if write_guard.is_some() {
        cmd.arg("-c").arg(format!(
            "core.hooksPath={}",
            state.storage.root.join("managed-hooks").display()
        ));
        cmd.env("ROOTYARD_DATABASE_URL", &state.config.database_url)
            .env("ROOTYARD_GIT_PATH", &state.config.git)
            .env("ROOTYARD_GIT_DIR", &path)
            .env("ROOTYARD_DATA_ROOT", &state.storage.root)
            .env("ROOTYARD_GIT_TIMEOUT_SECONDS", state.config.git_timeout.as_secs().to_string());
        if let Ok(node_id) = std::env::var("ROOTYARD_NODE_ID") {
            cmd.env("ROOTYARD_NODE_ID", node_id);
        }
        // Storage::git clears the inherited environment. Forward only the
        // server's trusted transport inputs required by managed native hooks.
        for name in [
            "ROOTYARD_PG_CA_PEM", "ROOTYARD_PG_CLIENT_CERT_PEM", "ROOTYARD_PG_CLIENT_KEY_PEM",
            "ROOTYARD_OBJECT_STORE_ENDPOINT", "ROOTYARD_OBJECT_STORE_BUCKET",
            "ROOTYARD_OBJECT_STORE_REGION", "ROOTYARD_OBJECT_STORE_ACCESS_KEY",
            "ROOTYARD_OBJECT_STORE_SECRET_KEY", "ROOTYARD_OBJECT_STORE_SESSION_TOKEN",
            "ROOTYARD_LFS_POINTER_VERIFY_BYTES",
        ] {
            if let Some(value) = std::env::var_os(name) { cmd.env(name, value); }
        }
    }
    cmd.arg("http-backend")
        .env("GIT_PROJECT_ROOT", project_root)
        .env("PATH_INFO", format!("/{repository_dir}/{endpoint}"))
        .env("GIT_HTTP_EXPORT_ALL", "1")
        .env("REQUEST_METHOD", parts.method.as_str())
        .env("QUERY_STRING", parts.uri.query().unwrap_or(""))
        .env("REMOTE_USER", &remote_user)
        .env("REMOTE_ADDR", "127.0.0.1")
        .env("GIT_HTTP_MAX_REQUEST_BUFFER", "10485760")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(value) = parts.headers.get(header::CONTENT_TYPE) {
        cmd.env(
            "CONTENT_TYPE",
            value.to_str().map_err(|_| Error::bad_request())?,
        );
    }
    if let Some(value) = parts
        .headers
        .get(header::CONTENT_LENGTH)
        .filter(|_| !gzipped)
    {
        cmd.env(
            "CONTENT_LENGTH",
            value.to_str().map_err(|_| Error::bad_request())?,
        );
    }
    if let Some(value) = parts.headers.get("git-protocol") {
        cmd.env(
            "GIT_PROTOCOL",
            value.to_str().map_err(|_| Error::bad_request())?,
        );
    }
    let memory = state.config.git_memory_bytes;
    let file_size = state.config.max_repo_bytes;
    let cpu = state.config.git_timeout.as_secs().max(1);
    unsafe {
        cmd.pre_exec(move || {
            if libc::setpgid(0, 0) == -1 {
                return Err(io::Error::last_os_error());
            }
            for (resource, limit) in [
                (libc::RLIMIT_AS, memory),
                (libc::RLIMIT_CPU, cpu),
                (libc::RLIMIT_FSIZE, file_size),
                (libc::RLIMIT_NOFILE, 256),
            ] {
                let value = libc::rlimit {
                    rlim_cur: limit,
                    rlim_max: limit,
                };
                if libc::setrlimit(resource, &value) == -1 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let operation = if write_guard.is_some() {
        let identity = identity.as_ref().ok_or_else(Error::unauthorized)?;
        let operation = journal::begin(
            &state.storage.root,
            repo.id,
            identity.id,
            identity.username.clone(),
            identity.token_id,
            repo.storage_generation,
        )
        .map_err(Error::internal)?;
        cmd.env("ROOTYARD_JOURNAL_OPERATION", &operation.path);
        Some(operation)
    } else {
        None
    };
    if let Some(plan) = &job_plan {
        let (_, _, current) = crate::ci_checkouts::authority::authenticate_principal(
            &state,
            &parts.headers,
            owner,
            name,
            pin_oid.unwrap(),
        )
        .await?;
        if &current != plan {
            return Err(Error::unauthorized());
        }
    }
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(error) => {
            let _ = reliability::complete(&state, operation).await;
            return Err(Error::internal(error));
        }
    };
    let pid = child.id().ok_or_else(Error::bad_request)? as i32;
    let mut stdin = child.stdin.take().expect("piped stdin");
    let stdout = child.stdout.take().expect("piped stdout");
    let mut stderr = child.stderr.take().expect("piped stderr");
    let input_prefix = receive.map(|commands| commands.bytes).unwrap_or_default();
    let input = tokio::spawn(async move {
        let mut decoded_bytes = input_prefix.len() as u64;
        if decoded_bytes > max_input { return Err(io::Error::other("decoded request size limit exceeded")); }
        stdin.write_all(&input_prefix).await?;
        let mut buf = [0u8; 32 * 1024];
        loop {
            let n = input_reader.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            decoded_bytes = decoded_bytes.saturating_add(n as u64);
            if decoded_bytes > max_input {
                return Err(io::Error::other("decoded request size limit exceeded"));
            }
            stdin.write_all(&buf[..n]).await?;
        }
        stdin.shutdown().await
    });
    let stderr = tokio::spawn(async move {
        // Drain continuously, bounded memory. Do not forward untrusted Git diagnostics
        // into logs where paths, commit data or secrets could be disclosed.
        let mut buf = [0u8; 4096];
        while matches!(stderr.read(&mut buf).await,Ok(n) if n>0) {}
    });
    let mut process = Process {
        child,
        input: Some(input),
        stderr,
        pid,
    };
    let mut stdout = BufReader::with_capacity(16 * 1024, stdout);
    let headers = match tokio::time::timeout_at(deadline, read_headers(&mut stdout)).await {
        Ok(Ok(headers)) => headers,
        result => {
            process.stop().await;
            state.transfer_metrics.record_failure();
            let _ = reliability::complete(&state, operation).await;
            return Err(match result {
                Err(_) => Error::timeout(),
                Ok(Err(error)) => Error::internal(error),
                _ => unreachable!(),
            });
        }
    };
    // A native upload-pack refusal is an ERR pkt-line followed by a nonzero
    // exit. Publishing a streaming 200 first is racy: an input BrokenPipe or
    // final body error can discard the queued ERR before HTTP flushes it.
    // Inspect just the first bounded packet for job RPCs before committing
    // headers. Never turn a failed/truncated PACK into a successful response.
    let prefix = if job && parts.method == Method::POST && headers.0.is_success() {
        match tokio::time::timeout_at(
            deadline,
            job_response_prefix(&mut stdout, state.config.max_output_bytes),
        )
        .await
        {
            Ok(Ok((prefix, false))) => prefix,
            result => {
                process.stop().await;
                state.transfer_metrics.record_failure();
                return Err(match result {
                    Ok(Ok((_, true))) => Error(StatusCode::FORBIDDEN, "Git target request denied"),
                    Err(_) => Error::timeout(),
                    Ok(Err(error)) => Error::internal(error),
                    _ => unreachable!(),
                });
            }
        }
    } else {
        Vec::new()
    };
    if let Err(error) = transfer_authorized(&state, identity.as_ref(), job_plan.as_ref(),
        job_principal.as_ref(), &repo, write).await {
        process.stop().await;
        let _ = reliability::complete(&state, operation).await;
        return Err(Error::internal(error));
    }
    // Reinsert the inspected bytes unchanged. Existing transfer accounting,
    // process-exit checks, input errors and deadlines still cover every byte.
    let mut stdout = std::io::Cursor::new(prefix).chain(stdout);
    let mut response = Response::builder()
        .status(headers.0)
        .header(header::CONTENT_TYPE, headers.1)
        .header(header::CACHE_CONTROL, "no-store")
        .header("x-content-type-options", "nosniff");
    if write {
        response = response.header("x-rootyard-write-policy", "fast-forward-only");
    }
    let max_output = state.config.max_output_bytes;
    // Drive pipes independently of response polling. Otherwise a client that stops
    // reading could freeze the deadline, retain its permit and block a repository.
    let (sender, mut receiver) = tokio::sync::mpsc::channel::<Bytes>(8);
    let failed = Arc::new(std::sync::atomic::AtomicBool::new(
        headers.0.is_client_error() || headers.0.is_server_error(),
    ));
    let producer_failed = failed.clone();
    let admitted_repo = repo.clone();
    tokio::spawn(async move {
        let _permit: OwnedSemaphorePermit = permit;
        let _write_guard: Option<OwnedMutexGuard<()>> = write_guard;
        let ref_guard = ref_guard;
        let _read_guard: Option<OwnedRwLockReadGuard<()>> = read_guard;
        let snapshot_lease = snapshot_lease;
        let state = state;
        let transfer = async {
            let mut total = 0u64;
            let mut buf = vec![0u8; 32 * 1024];
            let mut recheck_tick = tokio::time::interval(std::time::Duration::from_secs(1));
            recheck_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            transfer_authorized(&state, identity.as_ref(), job_plan.as_ref(),
                job_principal.as_ref(), &admitted_repo, write).await?;
            if let Some(guard) = &ref_guard { guard.ensure_active().map_err(|_| io::Error::other("ref publication guard lost"))?; }
            if let Some(lease) = &snapshot_lease { lease.ensure_active().map_err(|_| io::Error::other("storage read lease lost"))?; }
            loop {
                let next = if let Some(input) = process.input.as_mut() {
                    tokio::select! {
                        value = stdout.read(&mut buf) => value.map(Some),
                        value = input => {
                            process.input = None;
                            value.map_err(io::Error::other).and_then(|v|v).map(|_|None)
                        }
                        _ = recheck_tick.tick() => {
                            if let Some(guard) = &ref_guard { guard.ensure_active().map_err(|_| io::Error::other("ref publication guard lost"))?; }
                            transfer_authorized(&state, identity.as_ref(), job_plan.as_ref(),
                                job_principal.as_ref(), &admitted_repo, write).await?;
                            if let Some(lease) = &snapshot_lease { lease.ensure_active().map_err(|_| io::Error::other("storage read lease lost"))?; }
                            continue;
                        }
                        _ = sender.closed() => return Err(io::Error::other("client disconnected")),
                    }
                } else {
                    tokio::select! {
                        value = stdout.read(&mut buf) => value.map(Some),
                        _ = recheck_tick.tick() => {
                            if let Some(guard) = &ref_guard { guard.ensure_active().map_err(|_| io::Error::other("ref publication guard lost"))?; }
                            transfer_authorized(&state, identity.as_ref(), job_plan.as_ref(),
                                job_principal.as_ref(), &admitted_repo, write).await?;
                            if let Some(lease) = &snapshot_lease { lease.ensure_active().map_err(|_| io::Error::other("storage read lease lost"))?; }
                            continue;
                        }
                        _ = sender.closed() => return Err(io::Error::other("client disconnected")),
                    }
                };
                let Some(n) = next? else {
                    continue;
                };
                if n == 0 {
                    break;
                }
                transfer_authorized(&state, identity.as_ref(), job_plan.as_ref(),
                    job_principal.as_ref(), &admitted_repo, write).await?;
                if let Some(guard) = &ref_guard { guard.ensure_active().map_err(|_| io::Error::other("ref publication guard lost"))?; }
                if let Some(lease) = &snapshot_lease { lease.ensure_active().map_err(|_| io::Error::other("storage read lease lost"))?; }
                total = total.saturating_add(n as u64);
                if total > max_output {
                    return Err(io::Error::other("Git response size limit exceeded"));
                }
                let slot = loop {
                    tokio::select! {
                        slot = sender.reserve() => break slot.map_err(|_| io::Error::other("client disconnected"))?,
                        _ = recheck_tick.tick() => {
                            if let Some(guard) = &ref_guard { guard.ensure_active().map_err(|_| io::Error::other("ref publication guard lost"))?; }
                            transfer_authorized(&state, identity.as_ref(), job_plan.as_ref(),
                                job_principal.as_ref(), &admitted_repo, write).await?;
                            if let Some(lease) = &snapshot_lease { lease.ensure_active().map_err(|_| io::Error::other("storage read lease lost"))?; }
                        }
                    }
                };
                slot.send(Bytes::copy_from_slice(&buf[..n]));
                state.transfer_metrics.add_sent_bytes(n as u64);
            }
            if let Some(input) = process.input.as_mut() {
                input.await.map_err(io::Error::other)??;
                process.input = None;
            }
            let status = process.finish().await?;
            if !status.success() {
                return Err(io::Error::other("Git subprocess failed"));
            }
            if write {
                if let Some(guard) = &ref_guard { guard.ensure_active().map_err(|_| io::Error::other("ref publication guard lost"))?; }
                crate::sharding::fencing::check_before_push(&state, &admitted_repo).await
                    .map_err(|_| io::Error::other("storage fence changed during Git write"))?;
            }
            Ok::<(), io::Error>(())
        };
        if !matches!(
            tokio::time::timeout_at(deadline, transfer).await,
            Ok(Ok(()))
        ) {
            producer_failed.store(true, std::sync::atomic::Ordering::Release);
        }
        process.stop().await;
        // Drop is also a last-resort guard if this task itself is cancelled.
        drop(process);
        if let Err(error) = reliability::complete(&state, operation).await {
            producer_failed.store(true, std::sync::atomic::Ordering::Release);
            eprintln!("rootyard: push evidence requires recovery: {error:#}");
        }
        if producer_failed.load(std::sync::atomic::Ordering::Acquire) {
            state.transfer_metrics.record_failure();
        } else {
            state.transfer_metrics.record_success();
        }
        drop(sender);
    });
    let stream = async_stream::try_stream! {
        while let Some(bytes) = receiver.recv().await { yield bytes; }
        if failed.load(std::sync::atomic::Ordering::Acquire) {
            Err(io::Error::other("Git transfer failed, timed out, or exceeded limits"))?;
        }
    };
    let stream: std::pin::Pin<
        Box<dyn futures_util::Stream<Item = Result<Bytes, io::Error>> + Send>,
    > = Box::pin(stream);
    response
        .body(Body::from_stream(stream))
        .map_err(Error::internal)
}
