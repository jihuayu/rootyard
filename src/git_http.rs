use crate::{
    AppState, Error, auth,
    db::{self, Repository},
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
    sync::{OwnedMutexGuard, OwnedSemaphorePermit},
    task::JoinHandle,
    time::Instant,
};

struct Process {
    child: Child,
    input: Option<JoinHandle<io::Result<()>>>,
    stderr: JoinHandle<()>,
    pid: i32,
}
impl Process {
    async fn finish(&mut self) -> io::Result<std::process::ExitStatus> {
        // Observe leader exit without reaping it: the unreaped PID reserves the
        // process-group ID while we clean any surviving descendants. Tokio's
        // Child::wait would reap too early for a safe group signal afterwards.
        loop {
            let exited = {
                let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
                let result = unsafe {
                    libc::waitid(
                        libc::P_PID,
                        self.pid as u32,
                        info.as_mut_ptr(),
                        libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                    )
                };
                if result != 0 {
                    return Err(io::Error::last_os_error());
                }
                unsafe { info.assume_init().si_pid() != 0 }
            };
            if exited {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        unsafe {
            libc::kill(-self.pid, libc::SIGKILL);
        }
        self.wait_group_quiescent().await;
        let status = self.child.wait().await?;
        self.pid = 0;
        Ok(status)
    }
    async fn wait_group_quiescent(&self) {
        // Keep leader unreaped, reserving PGID, until every member is dead or
        // zombie. SIGKILL delivery alone is not proof a descendant stopped.
        let started = Instant::now();
        let mut reported = false;
        while !matches!(group_quiescent(self.pid), Ok(true)) {
            if !reported && started.elapsed() > std::time::Duration::from_secs(5) {
                eprintln!(
                    "rootyard: process group cleanup blocked; retaining write lock and capacity"
                );
                reported = true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }
    async fn stop(&mut self) {
        if let Some(input) = &self.input {
            input.abort();
        }
        if self.pid <= 0 {
            return;
        }
        // Keep the leader unreaped for the entire grace period. Otherwise an
        // early leader exit could permit PGID reuse while descendants remain.
        unsafe {
            libc::kill(-self.pid, libc::SIGTERM);
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        unsafe {
            libc::kill(-self.pid, libc::SIGKILL);
        }
        self.wait_group_quiescent().await;
        let _ = self.child.wait().await;
        self.pid = 0;
    }
}
fn group_quiescent(group: i32) -> io::Result<bool> {
    for entry in std::fs::read_dir("/proc")? {
        let entry = entry?;
        if entry.file_name().to_string_lossy().parse::<u32>().is_err() {
            continue;
        }
        // Controlled Git children never change user identity. A restricted
        // /proc may deny other users' processes; they cannot belong to our group.
        use std::os::unix::fs::MetadataExt;
        match entry.metadata() {
            Ok(meta) if meta.uid() != unsafe { libc::geteuid() } => continue,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
            _ => {}
        }
        let stat = match std::fs::read_to_string(entry.path().join("stat")) {
            Ok(stat) => stat,
            Err(error)
                if error.kind() == io::ErrorKind::NotFound
                    || error.raw_os_error() == Some(libc::ESRCH) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        };
        let Some((_, rest)) = stat.rsplit_once(") ") else {
            return Err(io::Error::other("invalid proc stat"));
        };
        let fields: Vec<_> = rest.split_whitespace().collect();
        if fields.len() < 3 {
            return Err(io::Error::other("invalid proc stat"));
        }
        if fields[2].parse::<i32>().ok() == Some(group) && fields[0] != "Z" && fields[0] != "X" {
            return Ok(false);
        }
    }
    Ok(true)
}
impl Drop for Process {
    fn drop(&mut self) {
        // The process group covers http-backend, receive/upload-pack and their workers.
        // kill_on_drop only covers the immediate child, which is insufficient here.
        if self.pid > 0 {
            unsafe {
                libc::kill(-self.pid, libc::SIGKILL);
            }
        }
        let _ = self.child.start_kill();
        if let Some(input) = &self.input {
            input.abort();
        }
        self.stderr.abort();
    }
}

/// Bounded read-only maintenance command using the same process-group cleanup.
pub(crate) async fn collect_git_output(
    command: tokio::process::Command,
    limit: usize,
    timeout: std::time::Duration,
) -> anyhow::Result<Vec<u8>> {
    collect_git_output_input(command, limit, timeout, Stdio::null()).await
}

pub(crate) async fn collect_git_output_input(
    mut command: tokio::process::Command,
    limit: usize,
    timeout: std::time::Duration,
    input: Stdio,
) -> anyhow::Result<Vec<u8>> {
    command
        .stdin(input)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn()?;
    let pid = child
        .id()
        .ok_or_else(|| io::Error::other("missing Git PID"))? as i32;
    let mut stdout = child.stdout.take().expect("piped stdout");
    let mut stderr = child.stderr.take().expect("piped stderr");
    let drain = tokio::spawn(async move {
        let mut bytes = [0u8; 4096];
        while matches!(stderr.read(&mut bytes).await,Ok(n) if n>0) {}
    });
    let mut process = Process {
        child,
        input: None,
        stderr: drain,
        pid,
    };
    let mut output = Vec::new();
    let result = tokio::time::timeout(timeout, async {
        (&mut stdout)
            .take(limit as u64 + 1)
            .read_to_end(&mut output)
            .await?;
        if output.len() > limit {
            return Err(io::Error::other("maintenance output exceeds limit"));
        }
        if !process.finish().await?.success() {
            return Err(io::Error::other("read-only Git command failed"));
        }
        Ok::<(), io::Error>(())
    })
    .await;
    process.stop().await;
    result.map_err(|_| io::Error::other("maintenance Git command timed out"))??;
    Ok(output)
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
    let (pin_oid, route_path) = if state.mirror_primary.is_some() {
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
    let (identity, repo, job_plan) = if let Some((identity, repo)) = delegation {
        (identity, repo, None)
    } else if job {
        let (identity, repo, plan) = crate::ci_checkouts::authenticate(
            &state,
            &parts.headers,
            owner,
            name,
            pin_oid.unwrap(),
        )
        .await?;
        (identity, repo, Some(plan))
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
        (identity, repo, None)
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
    let write_guard = if write && parts.method == Method::POST {
        Some(
            tokio::time::timeout_at(deadline, state.storage.write_lock(repo.id))
                .await
                .map_err(|_| Error::timeout())?,
        )
    } else {
        None
    };
    if write_guard.is_some() {
        reliability::before_push(&state, &repo)
            .await
            .map_err(Error::internal)?;
    }
    let path = if let Some(oid) = pin_oid {
        if job {
            crate::mirror::job_path(&state, &repo, oid).await?
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
    let gzipped = parts
        .headers
        .get(header::CONTENT_ENCODING)
        .is_some_and(|v| v == "gzip" || v == "x-gzip");
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
    }
    cmd.arg("http-backend")
        .env("GIT_PROJECT_ROOT", project_root)
        .env("PATH_INFO", format!("/{repository_dir}/{endpoint}"))
        .env("GIT_HTTP_EXPORT_ALL", "1")
        .env("REQUEST_METHOD", parts.method.as_str())
        .env("QUERY_STRING", parts.uri.query().unwrap_or(""))
        .env("REMOTE_USER", &identity.username)
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
        let (_, _, current) = crate::ci_checkouts::authenticate(
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
    let max_input = state.config.max_request_bytes;
    let input_metrics = state.transfer_metrics.clone();
    let input = tokio::spawn(async move {
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
        let mut reader: std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send>> = if gzipped {
            let mut decoder =
                async_compression::tokio::bufread::GzipDecoder::new(BufReader::new(reader));
            decoder.multiple_members(true);
            Box::pin(decoder)
        } else {
            Box::pin(reader)
        };
        let mut decoded_bytes = 0u64;
        let mut buf = [0u8; 32 * 1024];
        loop {
            let n = reader.read(&mut buf).await?;
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
        let state = state;
        let transfer = async {
            let mut total = 0u64;
            let mut buf = vec![0u8; 32 * 1024];
            loop {
                let next = if let Some(input) = process.input.as_mut() {
                    tokio::select! {
                        value = stdout.read(&mut buf) => value.map(Some),
                        value = input => {
                            process.input = None;
                            value.map_err(io::Error::other).and_then(|v|v).map(|_|None)
                        }
                        _ = sender.closed() => return Err(io::Error::other("client disconnected")),
                    }
                } else {
                    tokio::select! {
                        value = stdout.read(&mut buf) => value.map(Some),
                        _ = sender.closed() => return Err(io::Error::other("client disconnected")),
                    }
                };
                let Some(n) = next? else {
                    continue;
                };
                if n == 0 {
                    break;
                }
                total = total.saturating_add(n as u64);
                if total > max_output {
                    return Err(io::Error::other("Git response size limit exceeded"));
                }
                sender
                    .send(Bytes::copy_from_slice(&buf[..n]))
                    .await
                    .map_err(|_| io::Error::other("client disconnected"))?;
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
        if reliability::complete(&state, operation).await.is_err() {
            producer_failed.store(true, std::sync::atomic::Ordering::Release);
            eprintln!("rootyard: push evidence requires recovery");
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

/// Buffer at most one protocol pkt-line (65,520 bytes, including its header).
/// Only a complete initial ERR packet is a refusal. Raw PACK, delimiters and
/// successful protocol packets remain ordinary streamed output; malformed or
/// truncated prefixes fail rather than masquerading as a clean Git response.
async fn job_response_prefix(
    reader: &mut (impl tokio::io::AsyncRead + Unpin),
    maximum: u64,
) -> io::Result<(Vec<u8>, bool)> {
    if maximum < 4 {
        return Err(io::Error::other("Git response size limit exceeded"));
    }
    let mut prefix = vec![0; 4];
    reader.read_exact(&mut prefix).await?;
    let length = std::str::from_utf8(&prefix)
        .ok()
        .and_then(|v| usize::from_str_radix(v, 16).ok());
    if let Some(length) = length {
        if length == 3 || length > 65520 || length as u64 > maximum {
            return Err(io::Error::other("invalid or oversized Git response packet"));
        }
        if length >= 4 {
            prefix.resize(length, 0);
            reader.read_exact(&mut prefix[4..]).await?;
        }
    } else if prefix != b"PACK" {
        return Err(io::Error::other("invalid Git response packet prefix"));
    }
    let denied = prefix
        .get(4..)
        .is_some_and(|payload| payload.starts_with(b"ERR "));
    Ok((prefix, denied))
}

fn route<'a>(
    method: &Method,
    path: &'a str,
    query: Option<&str>,
) -> Result<(&'a str, &'a str, &'a str, &'static str), Error> {
    // Validate the raw URL before any percent decoding. Repository paths are never
    // concatenated from this input: DB UUIDs choose directories.
    let segments: Vec<_> = path.split('/').collect();
    if segments.len() < 5 || !segments[0].is_empty() || segments[1] != "git" {
        return Err(Error::not_found());
    }
    let owner = segments[2];
    let name = segments[3]
        .strip_suffix(".git")
        .ok_or_else(Error::not_found)?;
    if !db::valid_name(owner) || !db::valid_name(name) {
        return Err(Error::not_found());
    }
    if segments.len() == 6
        && segments[4] == "info"
        && segments[5] == "refs"
        && method == Method::GET
    {
        let service = match query {
            Some("service=git-upload-pack") => "git-upload-pack",
            Some("service=git-receive-pack") => "git-receive-pack",
            _ => return Err(Error::bad_request()),
        };
        Ok((owner, name, "info/refs", service))
    } else if segments.len() == 5 && method == Method::POST && query.is_none() {
        let service = match segments[4] {
            "git-upload-pack" => "git-upload-pack",
            "git-receive-pack" => "git-receive-pack",
            _ => return Err(Error::not_found()),
        };
        Ok((owner, name, segments[4], service))
    } else {
        Err(Error::not_found())
    }
}
fn validate_headers(
    headers: &HeaderMap,
    method: &Method,
    service: &str,
    limit: u64,
) -> Result<(), Error> {
    if let Some(value) = headers.get(header::CONTENT_ENCODING) {
        if value != "identity" && value != "gzip" && value != "x-gzip" {
            return Err(Error(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "unsupported request encoding",
            ));
        }
    }
    if let Some(value) = headers.get(header::CONTENT_LENGTH) {
        let size = value
            .to_str()
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .ok_or_else(Error::bad_request)?;
        if size > limit {
            return Err(Error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request size limit exceeded",
            ));
        }
    }
    if let Some(value) = headers.get("git-protocol") {
        if !matches!(value.to_str(), Ok("version=0" | "version=1" | "version=2")) {
            return Err(Error::bad_request());
        }
    }
    if method == Method::POST {
        let expected = format!("application/x-{service}-request");
        if headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            != Some(expected.as_str())
        {
            return Err(Error(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "invalid Git content type",
            ));
        }
    }
    Ok(())
}
async fn read_headers(
    reader: &mut BufReader<tokio::process::ChildStdout>,
) -> io::Result<(StatusCode, HeaderValue)> {
    let mut bytes = Vec::new();
    while bytes.len() < 8192 {
        bytes.push(reader.read_u8().await?);
        if bytes.ends_with(b"\r\n\r\n") || bytes.ends_with(b"\n\n") {
            break;
        }
    }
    if bytes.len() >= 8192 {
        return Err(io::Error::other("oversized CGI headers"));
    }
    let text = std::str::from_utf8(&bytes).map_err(io::Error::other)?;
    let mut status = StatusCode::OK;
    let mut content_type = HeaderValue::from_static("application/octet-stream");
    for line in text.lines() {
        if let Some((key, value)) = line.split_once(':') {
            let value = value.trim();
            if key.eq_ignore_ascii_case("status") {
                status = value
                    .split_whitespace()
                    .next()
                    .and_then(|v| v.parse::<u16>().ok())
                    .and_then(|v| StatusCode::from_u16(v).ok())
                    .ok_or_else(|| io::Error::other("invalid CGI status"))?;
            } else if key.eq_ignore_ascii_case("content-type") {
                content_type = HeaderValue::from_str(value).map_err(io::Error::other)?;
            }
        }
    }
    Ok((status, content_type))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn job_refusal_prefix_is_bounded_complete_and_preserves_success() {
        for bytes in [b"0008NAK\nPACKpartial".as_slice(), b"PACKpartial", b"0000"] {
            let mut source = bytes;
            let (prefix, denied) = job_response_prefix(&mut source, 1024).await.unwrap();
            assert!(!denied);
            assert_eq!([prefix, source.to_vec()].concat(), bytes);
        }
        let packet = b"0013ERR not our ref";
        let mut err_then_pack = &b"0013ERR not our refPACKmust-not-be-served"[..];
        assert_eq!(
            job_response_prefix(&mut err_then_pack, 1024).await.unwrap(),
            (packet.to_vec(), true)
        );
        assert_eq!(err_then_pack, b"PACKmust-not-be-served");
        let (mut writer, mut reader) = tokio::io::duplex(1);
        let write = tokio::spawn(async move {
            for byte in packet {
                writer.write_all(&[*byte]).await.unwrap();
            }
        });
        assert_eq!(
            job_response_prefix(&mut reader, 1024).await.unwrap(),
            (packet.to_vec(), true)
        );
        write.await.unwrap();
        for bytes in [
            b"0013ERR short".as_slice(),
            b"00",
            b"ffff",
            b"0008NA",
            b"0003",
            b"oops",
        ] {
            assert!(job_response_prefix(&mut &bytes[..], 1024).await.is_err());
        }
        assert!(job_response_prefix(&mut &packet[..], 8).await.is_err());
        assert!(job_response_prefix(&mut &packet[..], 3).await.is_err());
    }
    #[test]
    fn rejects_unsafe_routes() {
        for path in [
            "/git/alice/../config",
            "/git/alice/demo.git/config",
            "/git/alice/a%2fb.git/info/refs",
            "/git/alice/demo.git/objects/abc",
            "/git/alice/demo.git/info/refs/",
        ] {
            assert!(route(&Method::GET, path, Some("service=git-upload-pack")).is_err());
        }
        assert!(
            route(
                &Method::GET,
                "/git/alice/demo.git/info/refs",
                Some("service=git-upload-pack")
            )
            .is_ok()
        );
    }
}

#[cfg(test)]
mod process_tests {
    use super::*;

    async fn orphan_group() -> (Process, i32) {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("child.pid");
        let mut cmd = tokio::process::Command::new("/bin/sh");
        cmd.args(["-c", "sh -c 'trap \"\" TERM; echo $$ > \"$1\"; while :; do sleep 1; done' child \"$1\" & exit 0", "leader"])
            .arg(&pid_file).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
        unsafe {
            cmd.pre_exec(|| {
                if libc::setpgid(0, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = cmd.spawn().unwrap();
        let pid = child.id().unwrap() as i32;
        let process = Process {
            child,
            input: None,
            stderr: tokio::spawn(async {}),
            pid,
        };
        let started = Instant::now();
        let child_pid = loop {
            if let Ok(text) = std::fs::read_to_string(&pid_file) {
                if let Ok(pid) = text.trim().parse::<i32>() {
                    break pid;
                }
            }
            assert!(
                started.elapsed().as_secs() < 5,
                "test child failed to start"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        };
        (process, child_pid)
    }
    async fn assert_not_running(pid: i32) {
        let started = Instant::now();
        loop {
            match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
                Err(_) => return,
                Ok(text)
                    if text
                        .rsplit_once(") ")
                        .is_some_and(|(_, tail)| tail.starts_with('Z')) =>
                {
                    return;
                }
                _ => {}
            }
            assert!(
                started.elapsed().as_secs() < 5,
                "descendant survived group cleanup"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }
    #[tokio::test]
    async fn successful_leader_does_not_leave_descendants() {
        let (mut process, child_pid) = orphan_group().await;
        let leader = process.pid;
        assert!(process.finish().await.unwrap().success());
        assert_not_running(child_pid).await;
        assert!(
            !std::path::Path::new(&format!("/proc/{leader}")).exists(),
            "leader was not reaped"
        );
    }
    #[tokio::test]
    async fn timeout_cleans_term_ignoring_descendants_before_reaping() {
        let (mut process, child_pid) = orphan_group().await;
        let leader = process.pid;
        process.stop().await;
        assert_not_running(child_pid).await;
        assert!(
            !std::path::Path::new(&format!("/proc/{leader}")).exists(),
            "leader was not reaped"
        );
    }
}
