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

pub async fn handle(state: Arc<AppState>, request: Request<Body>) -> Result<Response<Body>, Error> {
    // A disconnected caller cannot cancel cleanup between acquiring the write
    // lock and starting the response producer. The owned task retains all guards.
    tokio::spawn(execute(state, request))
        .await
        .map_err(Error::internal)?
}
async fn execute(state: Arc<AppState>, request: Request<Body>) -> Result<Response<Body>, Error> {
    let (parts, body) = request.into_parts();
    let (owner, name, endpoint, service) =
        route(&parts.method, parts.uri.path(), parts.uri.query())?;
    let identity = auth::authenticate(&state.pool, &parts.headers).await?;
    if owner != identity.username {
        return Err(Error::not_found());
    }
    let write = service == "git-receive-pack";
    if write {
        auth::writable(&identity)?;
    }
    let row = state
        .pool
        .get()
        .await
        .map_err(Error::internal)?
        .query_opt(
            &format!("{} WHERE r.owner_id=$1 AND r.name=$2", db::REPO_SELECT),
            &[&identity.id, &name],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    let repo = Repository::from_row(&row);
    if repo.state != "ready" {
        return Err(Error(
            StatusCode::SERVICE_UNAVAILABLE,
            "repository not ready; recovery may be required",
        ));
    }
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
    let path = state
        .storage
        .verify_path(repo.id)
        .map_err(Error::internal)?;
    if write_guard.is_some() {
        let quota = state.config.max_repo_bytes;
        let size = tokio::task::spawn_blocking(move || storage::disk_bytes(&path, quota))
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
    if write_guard.is_some() {
        cmd.arg("-c").arg(format!(
            "core.hooksPath={}",
            state.storage.root.join("managed-hooks").display()
        ));
    }
    cmd.arg("http-backend")
        .env("GIT_PROJECT_ROOT", state.storage.root.join("repos"))
        .env("PATH_INFO", format!("/{}.git/{endpoint}", repo.id))
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
    let input = tokio::spawn(async move {
        let mut wire_bytes = 0u64;
        let stream = body.into_data_stream().map(move |chunk| {
            let chunk = chunk.map_err(io::Error::other)?;
            wire_bytes = wire_bytes.saturating_add(chunk.len() as u64);
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
            let _ = reliability::complete(&state, operation).await;
            return Err(match result {
                Err(_) => Error::timeout(),
                Ok(Err(error)) => Error::internal(error),
                _ => unreachable!(),
            });
        }
    };
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
    let failed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let producer_failed = failed.clone();
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
            }
            if let Some(input) = process.input.as_mut() {
                input.await.map_err(io::Error::other)??;
                process.input = None;
            }
            let status = process.finish().await?;
            if !status.success() {
                return Err(io::Error::other("Git subprocess failed"));
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
