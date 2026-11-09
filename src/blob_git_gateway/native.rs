//! Native Git execution and the temporary computed bare-repository view.
//!
//! Every child runs with a cleared environment, an owned HOME/template, no
//! system/global config, no hooks, no replacement objects, no grafts and no
//! ambient repository discovery. Each child is also a process-group leader with
//! OS CPU/AS/FSIZE/FD limits installed in `pre_exec`. Cancellation, timeout,
//! early exit and drop all kill and reap the *whole group*, then abort and join
//! the feeder/stdout/stderr tasks under a cleanup bound that is independent of
//! the request deadline. Output buffers are fixed ceilings; request bodies are
//! streamed to bounded files (optionally gzip-decoded with a separate expanded
//! byte ceiling), never collected into a large `Vec`.
use std::{
    io,
    path::{Path, PathBuf},
    pin::Pin,
    process::{ExitStatus, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use async_compression::tokio::write::GzipDecoder;
use axum::body::Body;
use bytes::Bytes;
use futures_util::StreamExt;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    process::{ChildStdout, Command},
    sync::{OwnedSemaphorePermit, mpsc},
    time::Instant,
};
use uuid::Uuid;

use super::{
    config::BlobGitNativeLimits,
    error::GatewayError,
    process_guard::{self, ProcessGuard},
    resource,
    session::ReadAuthorization,
    state::{BlobGitState, TempDir},
};
use crate::ref_store::GitObjectFormat;

/// Hard ceiling for any stdout that is collected in memory. Streaming output is
/// never collected; even an advertisement cannot make a `Vec` larger than this.
const MAX_CAPTURED_STDOUT: u64 = 16 * 1024 * 1024;
/// Native stderr is drained but never stored or logged.
const STDERR_DRAIN_LIMIT: u64 = 64 * 1024;
/// Re-check live read authorization at most once per second during a stream.
const REVALIDATE_INTERVAL: Duration = Duration::from_secs(1);
/// Each revalidation check has its own small bound, independent of a blocked
/// stdout read or response-body send.
const REVALIDATE_CHECK_LIMIT: Duration = Duration::from_secs(2);
/// Streaming chunk size for stdout and body spooling.
const IO_CHUNK_BYTES: usize = 64 * 1024;

/// Bounded captured process output.
pub(super) struct Captured {
    pub stdout: Vec<u8>,
    pub success: bool,
}

/// One owned temporary bare repository. The whole directory (repo, HOME and
/// template) is removed on drop; no path is exposed outside the gateway. The
/// process-group permit is held for the view's whole lifetime, so the global
/// native process budget covers every command and descendant of this view.
pub(super) struct TempGitView {
    dir: TempDir,
    repo: PathBuf,
    home: PathBuf,
    template: PathBuf,
    limits: BlobGitNativeLimits,
    _process: OwnedSemaphorePermit,
}

impl TempGitView {
    pub(super) async fn create(
        state: &BlobGitState,
        format: GitObjectFormat,
        deadline: Instant,
    ) -> Result<Self, GatewayError> {
        let process = state.native_process(deadline).await?;
        let dir = state.temp_dir("view")?;
        let home = dir.path().join("home");
        let template = dir.path().join("template");
        let repo = dir.path().join("repo.git");
        std::fs::create_dir_all(&home).map_err(|_| GatewayError::Internal("could not create a private HOME"))?;
        std::fs::create_dir_all(&template)
            .map_err(|_| GatewayError::Internal("could not create a private Git template"))?;
        let view = Self { dir, repo, home, template, limits: state.native_limits(), _process: process };
        let mut command = view.base_command(state.git_binary());
        command
            .current_dir(view.root())
            .env_remove("GIT_DIR")
            .arg("init")
            .arg("--bare")
            .arg("--quiet")
            .arg(format!("--object-format={}", format.as_str()))
            .arg("--template")
            .arg(&view.template)
            .arg(&view.repo);
        let captured = run_capture(command, None, 64 * 1024, deadline).await?;
        if !captured.success || !view.repo.is_dir() {
            return Err(GatewayError::Internal("could not initialize the temporary Git view"));
        }
        Ok(view)
    }

    pub(super) fn root(&self) -> &Path {
        self.dir.path()
    }

    pub(super) fn repo(&self) -> &Path {
        &self.repo
    }

    /// Environment-safe Git command bound to this view's bare repository.
    pub(super) fn command(&self, git: &Path) -> Command {
        let mut command = self.base_command(git);
        command.current_dir(self.root()).env("GIT_DIR", &self.repo);
        command
    }

    pub(super) fn command_with_protocol(&self, git: &Path, protocol: Option<&str>) -> Command {
        let mut command = self.command(git);
        if let Some(protocol) = protocol {
            command.env("GIT_PROTOCOL", protocol);
        }
        command
    }

    fn base_command(&self, git: &Path) -> Command {
        let mut command = Command::new(git);
        command
            .env_clear()
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", &self.home)
            .env("XDG_CACHE_HOME", &self.home)
            .env("PATH", "/usr/bin:/bin")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GIT_ATTR_NOSYSTEM", "1")
            .env("GIT_TEMPLATE_DIR", &self.template)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("GIT_NO_REPLACE_OBJECTS", "1")
            .env("GIT_GRAFT_FILE", "/dev/null")
            .env("GIT_CEILING_DIRECTORIES", self.root())
            .env("LC_ALL", "C")
            .env("GIT_AUTHOR_NAME", "Rootyard Gateway")
            .env("GIT_AUTHOR_EMAIL", "gateway@rootyard.invalid")
            .env("GIT_COMMITTER_NAME", "Rootyard Gateway")
            .env("GIT_COMMITTER_EMAIL", "gateway@rootyard.invalid")
            .arg("-c")
            .arg("core.hooksPath=/dev/null")
            .arg("-c")
            .arg("core.logAllRefUpdates=false")
            .arg("-c")
            .arg("gc.auto=0")
            .arg("-c")
            .arg("receive.autogc=false")
            .arg("-c")
            .arg("receive.unpackLimit=0")
            .arg("-c")
            .arg("receive.fsckObjects=true")
            .arg("-c")
            .arg("receive.denyNonFastForwards=false")
            .arg("-c")
            .arg("receive.denyDeletes=false")
            .arg("--no-replace-objects");
        command.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true);
        // CPU/AS/FSIZE/FD limits plus a second `setpgid` in the child. No argv,
        // environment, path or secret is logged or printed.
        resource::apply_native_limits(&mut command, &self.limits);
        command
    }
}

fn cleanup_bound() -> Instant {
    Instant::now() + process_guard::CLEANUP_LIMIT
}

/// Run one bounded command and collect bounded stdout. Stdin may come from one
/// already-spooled request file; it is copied concurrently with output so a
/// full pipe on either side cannot deadlock.
pub(super) async fn run_capture(
    command: Command,
    stdin_file: Option<&Path>,
    max_stdout: u64,
    deadline: Instant,
) -> Result<Captured, GatewayError> {
    let stdout_limit = max_stdout.min(MAX_CAPTURED_STDOUT);
    let stdin = match stdin_file {
        Some(path) => Some(
            tokio::fs::File::open(path)
                .await
                .map_err(|_| GatewayError::Internal("could not read the spooled Git request"))?,
        ),
        None => None,
    };
    let mut guard = ProcessGuard::spawn(command)?;
    let input = guard.child.stdin.take();
    let Some(stdout) = guard.child.stdout.take() else {
        let _ = guard.finish(cleanup_bound()).await;
        return Err(GatewayError::Internal("native Git stdout is unavailable"));
    };
    let Some(stderr) = guard.child.stderr.take() else {
        drop(stdout);
        let _ = guard.finish(cleanup_bound()).await;
        return Err(GatewayError::Internal("native Git stderr is unavailable"));
    };
    let feeder = match (stdin, input) {
        (None, input) => {
            drop(input);
            None
        }
        (Some(_), None) => {
            let _ = guard.finish(cleanup_bound()).await;
            return Err(GatewayError::Internal("native Git stdin is unavailable"));
        }
        (Some(mut file), Some(mut pipe)) => Some(tokio::spawn(async move {
            let _ = tokio::io::copy(&mut file, &mut pipe).await;
            let _ = pipe.shutdown().await;
        })),
    };
    let stdout_task = tokio::spawn(read_limited(stdout, stdout_limit));
    let stderr_task = tokio::spawn(drain_limited(stderr, STDERR_DRAIN_LIMIT));
    let leader = guard.wait_leader(deadline).await;
    let cleanup = cleanup_bound();
    let finish = guard.finish(cleanup).await;
    let stdout_result = if leader.is_ok() {
        join_bounded(stdout_task, cleanup).await
    } else {
        abort_join(stdout_task).await;
        None
    };
    let stderr_result = join_bounded(stderr_task, cleanup).await;
    if let Some(feeder) = feeder {
        if leader.is_ok() {
            let _ = join_bounded(feeder, cleanup).await;
        } else {
            abort_join(feeder).await;
        }
    }
    leader?;
    let status = match finish {
        Ok(status) => status,
        Err(_) => return Err(GatewayError::Internal("native Git process cleanup could not be completed")),
    };
    let (stdout_bytes, stdout_over) = match stdout_result {
        Some(Ok(value)) => value,
        Some(Err(_)) => return Err(GatewayError::Internal("native Git output failed")),
        None => return Err(GatewayError::Internal("native Git output task did not finish")),
    };
    let _ = stderr_result;
    if stdout_over {
        return Err(GatewayError::TooLarge);
    }
    Ok(Captured { stdout: stdout_bytes, success: status.success() })
}

/// Spool one HTTP body while decoding an optional `Content-Encoding`.
///
/// `wire_max` bounds the bytes read from the client and `expanded_max` bounds
/// the bytes written to `path`. For `gzip`/`x-gzip` the compressed stream is fed
/// through an async decoder, so a zip bomb is stopped by the expanded counter
/// without ever materializing the whole payload. `identity`/absent encoding is a
/// direct bounded stream. Returns the decoded byte count.
pub(super) async fn spool_body_with_encoding(
    body: Body,
    path: &Path,
    wire_max: u64,
    expanded_max: u64,
    encoding: Option<&str>,
    deadline: Instant,
) -> Result<u64, GatewayError> {
    let gzip = decode_encoding(encoding)?;
    let file =
        tokio::fs::File::create(path).await.map_err(|_| GatewayError::Internal("could not stage the request"))?;
    if gzip {
        spool_gzip(body, file, wire_max, expanded_max, deadline).await
    } else {
        spool_identity(body, file, wire_max, expanded_max, deadline).await
    }
}

fn decode_encoding(encoding: Option<&str>) -> Result<bool, GatewayError> {
    let Some(raw) = encoding else { return Ok(false) };
    let value = raw.trim();
    if value.is_empty() || value.eq_ignore_ascii_case("identity") {
        return Ok(false);
    }
    if value.eq_ignore_ascii_case("gzip") || value.eq_ignore_ascii_case("x-gzip") {
        return Ok(true);
    }
    Err(GatewayError::BadRequest("unsupported Git request content encoding"))
}

async fn spool_identity(
    body: Body,
    mut file: tokio::fs::File,
    wire_max: u64,
    expanded_max: u64,
    deadline: Instant,
) -> Result<u64, GatewayError> {
    let limit = wire_max.min(expanded_max);
    let mut stream = body.into_data_stream();
    let mut total: u64 = 0;
    loop {
        let chunk = match tokio::time::timeout_at(deadline, stream.next()).await {
            Ok(Some(Ok(chunk))) => chunk,
            Ok(Some(Err(_))) => return Err(GatewayError::BadRequest("request body could not be read")),
            Ok(None) => break,
            Err(_) => return Err(GatewayError::Timeout),
        };
        total = total.checked_add(chunk.len() as u64).ok_or(GatewayError::TooLarge)?;
        if total > limit {
            return Err(GatewayError::TooLarge);
        }
        match tokio::time::timeout_at(deadline, file.write_all(&chunk)).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) => return Err(GatewayError::Internal("could not stage the request")),
            Err(_) => return Err(GatewayError::Timeout),
        }
    }
    finish_file(file, deadline).await?;
    Ok(total)
}

async fn spool_gzip(
    body: Body,
    file: tokio::fs::File,
    wire_max: u64,
    expanded_max: u64,
    deadline: Instant,
) -> Result<u64, GatewayError> {
    let exceeded = Arc::new(AtomicBool::new(false));
    let writer = BoundedWriter::new(file, expanded_max, exceeded.clone());
    let mut decoder = GzipDecoder::new(writer);
    let mut stream = body.into_data_stream();
    let mut wire: u64 = 0;
    loop {
        let chunk = match tokio::time::timeout_at(deadline, stream.next()).await {
            Ok(Some(Ok(chunk))) => chunk,
            Ok(Some(Err(_))) => return Err(GatewayError::BadRequest("request body could not be read")),
            Ok(None) => break,
            Err(_) => return Err(GatewayError::Timeout),
        };
        wire = wire.checked_add(chunk.len() as u64).ok_or(GatewayError::TooLarge)?;
        if wire > wire_max {
            return Err(GatewayError::TooLarge);
        }
        match tokio::time::timeout_at(deadline, decoder.write_all(&chunk)).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) => return Err(spool_decode_error(&exceeded)),
            Err(_) => return Err(GatewayError::Timeout),
        }
    }
    match tokio::time::timeout_at(deadline, decoder.shutdown()).await {
        Ok(Ok(())) => {}
        Ok(Err(_)) => return Err(spool_decode_error(&exceeded)),
        Err(_) => return Err(GatewayError::Timeout),
    }
    let writer = decoder.into_inner();
    if exceeded.load(Ordering::Acquire) {
        return Err(GatewayError::TooLarge);
    }
    let total = writer.written();
    let file = writer.into_inner();
    finish_file(file, deadline).await?;
    Ok(total)
}

fn spool_decode_error(exceeded: &Arc<AtomicBool>) -> GatewayError {
    if exceeded.load(Ordering::Acquire) {
        GatewayError::TooLarge
    } else {
        GatewayError::BadRequest("compressed Git request body is invalid")
    }
}

async fn finish_file(mut file: tokio::fs::File, deadline: Instant) -> Result<(), GatewayError> {
    match tokio::time::timeout_at(deadline, file.flush()).await {
        Ok(Ok(())) => {}
        Ok(Err(_)) => return Err(GatewayError::Internal("could not stage the request")),
        Err(_) => return Err(GatewayError::Timeout),
    }
    match tokio::time::timeout_at(deadline, file.sync_all()).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) => Err(GatewayError::Internal("could not stage the request")),
        Err(_) => Err(GatewayError::Timeout),
    }
}

/// Counts decoded bytes and fails before the file can exceed `limit`.
struct BoundedWriter<W> {
    inner: W,
    written: u64,
    limit: u64,
    exceeded: Arc<AtomicBool>,
}

impl<W> BoundedWriter<W> {
    fn new(inner: W, limit: u64, exceeded: Arc<AtomicBool>) -> Self {
        Self { inner, written: 0, limit, exceeded }
    }

    fn written(&self) -> u64 {
        self.written
    }

    fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for BoundedWriter<W> {
    fn poll_write(self: Pin<&mut Self>, context: &mut Context<'_>, buffer: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buffer.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.written.saturating_add(buffer.len() as u64) > this.limit {
            this.exceeded.store(true, Ordering::Release);
            return Poll::Ready(Err(io::Error::other("expanded Git request body exceeds limit")));
        }
        let poll = Pin::new(&mut this.inner).poll_write(context, buffer);
        if let Poll::Ready(Ok(written)) = poll {
            this.written = this.written.saturating_add(written as u64);
        }
        poll
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(context)
    }
}

/// Stream native stdout as the HTTP response. The first chunk is awaited before
/// the response starts, so an immediate native refusal becomes a real HTTP
/// error; afterwards every read/send is bounded by the same absolute deadline
/// and by a live read-authorization check every second. `owner` keeps the local
/// computed view, request work directory, concurrency slot and byte lease alive
/// until the child process group has exited and been reaped.
pub(super) async fn spawn_stream<O: Send + 'static>(
    command: Command,
    stdin_file: Option<PathBuf>,
    max_stdout: u64,
    deadline: Instant,
    owner: O,
    authorization: ReadAuthorization,
) -> Result<Body, GatewayError> {
    let stdin = match stdin_file {
        Some(path) => Some(
            tokio::fs::File::open(&path)
                .await
                .map_err(|_| GatewayError::Internal("could not read the spooled Git request"))?,
        ),
        None => None,
    };
    let mut guard = ProcessGuard::spawn(command)?;
    let input = guard.child.stdin.take();
    let Some(mut stdout) = guard.child.stdout.take() else {
        let _ = guard.finish(cleanup_bound()).await;
        return Err(GatewayError::Internal("native Git stdout is unavailable"));
    };
    let Some(stderr) = guard.child.stderr.take() else {
        let _ = guard.finish(cleanup_bound()).await;
        return Err(GatewayError::Internal("native Git stderr is unavailable"));
    };
    let feeder = match (stdin, input) {
        (None, input) => {
            drop(input);
            None
        }
        (Some(_), None) => {
            let _ = guard.finish(cleanup_bound()).await;
            return Err(GatewayError::Internal("native Git stdin is unavailable"));
        }
        (Some(mut file), Some(mut pipe)) => Some(tokio::spawn(async move {
            let _ = tokio::io::copy(&mut file, &mut pipe).await;
            let _ = pipe.shutdown().await;
        })),
    };
    let stderr_task = tokio::spawn(drain_limited(stderr, STDERR_DRAIN_LIMIT));
    let mut resources = StreamGuard { guard, feeder, stderr: Some(stderr_task), owner: Some(owner) };
    let mut buffer = vec![0u8; IO_CHUNK_BYTES];
    let mut next_check = Instant::now() + REVALIDATE_INTERVAL;
    let first = loop {
        let next = tokio::select! {
            biased;
            _ = tokio::time::sleep_until(next_check) => {
                let outcome = revalidate(&authorization, deadline).await;
                next_check = Instant::now() + REVALIDATE_INTERVAL;
                match outcome {
                    Ok(()) => None,
                    Err(error) => {
                        let _ = resources.finish(cleanup_bound()).await;
                        return Err(error);
                    }
                }
            }
            read = tokio::time::timeout_at(deadline, stdout.read(&mut buffer)) => {
                match read {
                    Ok(Ok(0)) => {
                        let status = resources.finish(cleanup_bound()).await;
                        return Err(match status {
                            Ok(status) if status.success() => GatewayError::Internal("native Git returned an empty response"),
                            _ => GatewayError::Internal("native Git request failed"),
                        });
                    }
                    Ok(Ok(read)) => Some(Bytes::copy_from_slice(&buffer[..read])),
                    Ok(Err(_)) => {
                        let _ = resources.finish(cleanup_bound()).await;
                        return Err(GatewayError::Internal("native Git output could not be read"));
                    }
                    Err(_) => {
                        let _ = resources.finish(cleanup_bound()).await;
                        return Err(GatewayError::Timeout);
                    }
                }
            }
        };
        if let Some(first) = next {
            break first;
        }
    };
    let first_len = first.len() as u64;
    if first_len > max_stdout {
        let _ = resources.finish(cleanup_bound()).await;
        return Err(GatewayError::TooLarge);
    }
    // Startup/native preparation may have outlived the last authorization
    // check. Admit no first payload until the live authority is checked again.
    if let Err(error) = revalidate(&authorization, deadline).await {
        let _ = resources.finish(cleanup_bound()).await;
        return Err(error);
    }
    let (sender, receiver) = mpsc::channel::<Result<Bytes, io::Error>>(4);
    if sender.send(Ok(first)).await.is_err() {
        let _ = resources.finish(cleanup_bound()).await;
        return Err(GatewayError::Internal("Git response body was not consumed"));
    }
    tokio::spawn(produce_stream(
        resources,
        stdout,
        buffer,
        sender,
        authorization,
        next_check,
        first_len,
        max_stdout,
        deadline,
    ));
    let stream = futures_util::stream::unfold(receiver, |mut receiver| async move {
        receiver.recv().await.map(|item| (item, receiver))
    });
    Ok(Body::from_stream(stream))
}

/// Async cleanup owner for one streaming child. Field order matters: the
/// process guard drops (and kills the group) before the owner's view/work
/// directory is removed. The explicit `finish` path aborts and joins every task.
struct StreamGuard<O> {
    guard: ProcessGuard,
    feeder: Option<tokio::task::JoinHandle<()>>,
    stderr: Option<tokio::task::JoinHandle<io::Result<(u64, bool)>>>,
    owner: Option<O>,
}

impl<O> StreamGuard<O> {
    async fn finish(&mut self, bound: Instant) -> io::Result<ExitStatus> {
        let status = self.guard.finish(bound).await;
        if let Some(feeder) = self.feeder.take() {
            abort_join(feeder).await;
        }
        if let Some(stderr) = self.stderr.take() {
            abort_join(stderr).await;
        }
        self.owner.take();
        status
    }
}

impl<O> Drop for StreamGuard<O> {
    fn drop(&mut self) {
        if let Some(feeder) = self.feeder.take() {
            feeder.abort();
        }
        if let Some(stderr) = self.stderr.take() {
            stderr.abort();
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn produce_stream<O: Send + 'static>(
    mut resources: StreamGuard<O>,
    mut stdout: ChildStdout,
    mut buffer: Vec<u8>,
    sender: mpsc::Sender<Result<Bytes, io::Error>>,
    authorization: ReadAuthorization,
    mut next_check: Instant,
    mut total: u64,
    max_stdout: u64,
    deadline: Instant,
) {
    let mut failed = false;
    loop {
        let mut auth_failed = false;
        let mut read_failed = false;
        let read = tokio::select! {
            biased;
            _ = sender.closed() => {
                read_failed = true;
                None
            }
            _ = tokio::time::sleep_until(next_check) => {
                auth_failed = revalidate(&authorization, deadline).await.is_err();
                next_check = Instant::now() + REVALIDATE_INTERVAL;
                None
            }
            read = tokio::time::timeout_at(deadline, stdout.read(&mut buffer)) => match read {
                Ok(Ok(read)) => Some(read),
                _ => {
                    read_failed = true;
                    None
                }
            },
        };
        if auth_failed || read_failed {
            failed = true;
            break;
        }
        let Some(read) = read else { continue };
        if read == 0 {
            break;
        }
        total = total.saturating_add(read as u64);
        if total > max_stdout {
            failed = true;
            break;
        }
        let chunk = Bytes::copy_from_slice(&buffer[..read]);
        if !send_with_revalidation(&sender, &authorization, &mut next_check, chunk, deadline).await {
            failed = true;
            break;
        }
    }
    let cleanup = cleanup_bound();
    let status = resources.finish(cleanup).await;
    let success = !failed && matches!(status, Ok(ref status) if status.success());
    if !success {
        // The body is already streaming, so a failed revalidation or a native
        // failure terminates the body with an error. It is never reported as a
        // successful Smart-HTTP stream.
        let _ = tokio::time::timeout_at(
            cleanup,
            sender.send(Err(io::Error::other("native Git response could not be completed"))),
        )
        .await;
    }
    drop(sender);
}

async fn send_with_revalidation(
    sender: &mpsc::Sender<Result<Bytes, io::Error>>,
    authorization: &ReadAuthorization,
    next_check: &mut Instant,
    chunk: Bytes,
    deadline: Instant,
) -> bool {
    let mut pending = Some(chunk);
    loop {
        tokio::select! {
            biased;
            _ = tokio::time::sleep_until(*next_check) => {
                let outcome = revalidate(authorization, deadline).await;
                *next_check = Instant::now() + REVALIDATE_INTERVAL;
                if outcome.is_err() {
                    return false;
                }
            }
            permit = tokio::time::timeout_at(deadline, sender.reserve()) => {
                return match permit {
                    Ok(Ok(permit)) => match pending.take() {
                        Some(chunk) => {
                            permit.send(Ok(chunk));
                            true
                        }
                        None => false,
                    },
                    _ => false,
                };
            }
        }
    }
}

async fn revalidate(authorization: &ReadAuthorization, deadline: Instant) -> Result<(), GatewayError> {
    let now = Instant::now();
    if now >= deadline {
        return Err(GatewayError::Timeout);
    }
    let check = (now + REVALIDATE_CHECK_LIMIT).min(deadline);
    match tokio::time::timeout_at(check, authorization.revalidate(check)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(error),
        Err(_) => Err(GatewayError::Timeout),
    }
}

async fn join_bounded<T>(mut task: tokio::task::JoinHandle<T>, bound: Instant) -> Option<T> {
    match tokio::time::timeout_at(bound, &mut task).await {
        Ok(Ok(value)) => Some(value),
        Ok(Err(_)) => None,
        Err(_) => {
            task.abort();
            let _ = tokio::time::timeout(Duration::from_millis(500), task).await;
            None
        }
    }
}

async fn abort_join<T>(task: tokio::task::JoinHandle<T>) {
    task.abort();
    let _ = tokio::time::timeout(Duration::from_millis(500), task).await;
}

async fn read_limited<R: AsyncRead + Unpin + Send + 'static>(mut reader: R, limit: u64) -> io::Result<(Vec<u8>, bool)> {
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            return Ok((bytes, false));
        }
        if bytes.len() as u64 + read as u64 > limit {
            return Ok((bytes, true));
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
}

/// Drain stderr without retaining it; only a byte count and overflow flag leave
/// the pipe. The content is never logged, stored or returned.
async fn drain_limited<R: AsyncRead + Unpin + Send + 'static>(mut reader: R, limit: u64) -> io::Result<(u64, bool)> {
    let mut total: u64 = 0;
    let mut over = false;
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            return Ok((total, over));
        }
        total = total.saturating_add(read as u64);
        if total > limit {
            over = true;
        }
    }
}

/// Read a bounded prefix of one spooled request (the command section precedes
/// the pack, so this never reads the whole pack).
pub(super) async fn read_prefix(path: &Path, limit: usize) -> Result<Vec<u8>, GatewayError> {
    let mut file = tokio::fs::File::open(path).await.map_err(|_| GatewayError::Internal("request is missing"))?;
    let mut bytes = vec![0u8; limit];
    let mut filled = 0usize;
    while filled < limit {
        let read = file.read(&mut bytes[filled..]).await.map_err(|_| GatewayError::Internal("request read failed"))?;
        if read == 0 {
            break;
        }
        filled += read;
    }
    bytes.truncate(filled);
    Ok(bytes)
}

/// Stream (hash, length) of one staged artifact. Never buffers the file.
pub(super) async fn file_digest(path: &Path) -> Result<(String, u64), GatewayError> {
    use sha2::{Digest, Sha256};
    let mut file =
        tokio::fs::File::open(path).await.map_err(|_| GatewayError::Internal("staged artifact is missing"))?;
    let mut hasher = Sha256::new();
    let mut length: u64 = 0;
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).await.map_err(|_| GatewayError::Internal("staged artifact read failed"))?;
        if read == 0 {
            break;
        }
        length = length.checked_add(read as u64).ok_or(GatewayError::TooLarge)?;
        hasher.update(&buffer[..read]);
    }
    Ok((hex::encode(hasher.finalize()), length))
}

pub(super) fn derived_uuid(domain: &str, operation: Uuid, extra: &[u8]) -> Uuid {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update(operation.as_bytes());
    hasher.update(extra);
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_compression::tokio::write::GzipEncoder;
    use tokio::io::AsyncWriteExt;

    async fn gzip(data: &[u8]) -> Vec<u8> {
        let mut encoder = GzipEncoder::new(Vec::new());
        encoder.write_all(data).await.expect("gzip write");
        encoder.shutdown().await.expect("gzip shutdown");
        encoder.into_inner()
    }

    fn body(chunks: Vec<Vec<u8>>) -> Body {
        let items = chunks.into_iter().map(|chunk| Ok::<_, std::io::Error>(Bytes::from(chunk))).collect::<Vec<_>>();
        Body::from_stream(futures_util::stream::iter(items))
    }

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(10)
    }

    #[tokio::test]
    async fn identity_spool_enforces_wire_and_expanded_bounds() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("identity.bin");
        let total = spool_body_with_encoding(
            body(vec![b"hello ".to_vec(), b"world".to_vec()]),
            &path,
            64,
            64,
            Some("identity"),
            deadline(),
        )
        .await
        .expect("identity body must spool");
        assert_eq!(total, 11);
        assert_eq!(std::fs::read(&path).expect("read"), b"hello world");

        let error = spool_body_with_encoding(
            body(vec![vec![b'x'; 65]]),
            &dir.path().join("too-large.bin"),
            64,
            64,
            None,
            deadline(),
        )
        .await
        .expect_err("over-limit identity body must be refused");
        assert_eq!(error, GatewayError::TooLarge);
    }

    #[tokio::test]
    async fn gzip_spool_decodes_and_enforces_expanded_bound() {
        let data = b"the quick brown fox jumps over the lazy dog".repeat(64);
        let compressed = gzip(&data).await;
        assert!(compressed.len() < data.len(), "test fixture must actually compress");
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("decoded.bin");
        let total = spool_body_with_encoding(
            body(vec![compressed.clone()]),
            &path,
            64 * 1024,
            data.len() as u64,
            Some("gzip"),
            deadline(),
        )
        .await
        .expect("gzip body must decode");
        assert_eq!(total, data.len() as u64);
        assert_eq!(std::fs::read(&path).expect("read"), data);
    }

    #[tokio::test]
    async fn gzip_spool_stops_zip_bomb_at_expanded_limit() {
        let data = vec![0u8; 1024 * 1024];
        let compressed = gzip(&data).await;
        assert!(compressed.len() < 4096, "zeros must compress far below the wire limit");
        let dir = tempfile::tempdir().expect("temp dir");
        let error = spool_body_with_encoding(
            body(vec![compressed]),
            &dir.path().join("bomb.bin"),
            64 * 1024,
            4096,
            Some("gzip"),
            deadline(),
        )
        .await
        .expect_err("expanded limit must stop a zip bomb");
        assert_eq!(error, GatewayError::TooLarge);
    }

    #[tokio::test]
    async fn unsupported_encoding_is_refused_without_spooling() {
        let dir = tempfile::tempdir().expect("temp dir");
        let error = spool_body_with_encoding(
            body(vec![b"x".to_vec()]),
            &dir.path().join("br.bin"),
            64,
            64,
            Some("br"),
            deadline(),
        )
        .await
        .expect_err("brotli is not a supported Git content encoding");
        assert!(matches!(error, GatewayError::BadRequest(_)));
        assert!(!dir.path().join("br.bin").exists(), "unsupported encoding must not create a staged file");
    }
}
