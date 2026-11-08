//! Stock Smart HTTP receive-pack against a disposable Pando session. Native
//! output is buffered and released only after the authoritative PG ref/outbox
//! transaction commits. A typed pre-commit ref CAS refusal replaces that native
//! success response with the negotiated receive-pack `ng` report; an ambiguous
//! commit or any other failure stays a distinct HTTP error.
use super::*;
use crate::pando_gateway::{prepare, publish, snapshot};
use axum::http::request::Parts;
use std::time::Duration;

const MAX_RECEIVE_REPLY: u64 = 8 * 1024 * 1024;

pub(super) async fn execute(
    state: Arc<AppState>,
    parts: Parts,
    body: Body,
    actor: Identity,
    repo: Repository,
    _permit: OwnedSemaphorePermit,
    deadline: Instant,
) -> Result<Response<Body>, Error> {
    let max_input = state.config.max_request_bytes;
    let input = receive::prepare(
        body,
        &parts.headers,
        max_input,
        state.transfer_metrics.clone(),
        true,
        if repo.object_format == "sha256" { 64 } else { 40 },
        deadline,
    )
    .await?;
    let commands = input.commands.as_ref().ok_or_else(Error::bad_request)?;
    let requested = commands.changes.clone();
    let refs = commands.refs.clone();
    let capabilities = commands.capabilities;
    let ref_guard =
        storage::ref_publication::acquire(&state.pool, repo.id, repo.storage_generation, &refs, deadline).await?;
    let snapshot_lease = storage::read_leases::shared(&state.pool, repo.id, deadline).await?;
    let read_guard = tokio::time::timeout_at(deadline, state.storage.read_snapshot_lock(repo.id))
        .await
        .map_err(|_| Error::timeout())?;
    let snapshot = Box::pin(snapshot::materialize(&state, &repo, &snapshot_lease, deadline)).await?;
    drop(read_guard);
    transfer_authorized(&state, Some(&actor), None, None, &repo, true).await.map_err(Error::internal)?;
    ref_guard.ensure_active()?;
    crate::sharding::fencing::check_before_push(&state, &repo).await?;
    let (status, content_type, reply) = ref_guard
        .guard(run_backend(&state, &parts, input, &actor, &repo, snapshot.path(), &snapshot_lease, deadline))
        .await??;
    if !status.is_success() {
        state.transfer_metrics.record_failure();
        return Err(Error(StatusCode::SERVICE_UNAVAILABLE, "Pando native receive failed"));
    }
    let tenant_id = owner_id(&state, &repo).await?;
    let prepared = Box::pin(prepare::stage(&state, &repo, tenant_id, &snapshot, &snapshot_lease, deadline)).await?;
    let Some(prepared) = prepared else {
        // Native receive-pack changed no ref in the disposable snapshot. If its
        // own negotiated report already refused every requested ref, that report
        // is the authoritative pre-commit answer: pass it through instead of
        // turning a Git `ng` into an opaque HTTP 409. Otherwise nothing was
        // accepted and the unchanged HTTP refusal remains.
        if !protocol::reports_rejection(&reply, &refs) {
            return Err(Error(StatusCode::CONFLICT, "Pando receive did not change refs"));
        }
        return receive_response(status, content_type, reply);
    };
    match Box::pin(publish::publish_typed(
        &state, &repo, &actor, tenant_id, &snapshot, &prepared, &requested, &ref_guard, deadline,
    ))
    .await
    {
        Ok(_) => {}
        Err(publish::PublishError::RefRejected(rejection)) => {
            // Proven before the PG transaction committed: no ref, operation,
            // event or outbox row changed, so every requested ref gets `ng`.
            // The buffered native `ok` lines are deliberately discarded.
            debug_assert!(
                !capabilities.atomic || rejection.refs == refs,
                "atomic refusal must cover every requested ref"
            );
            let reply = protocol::rejected_refs_report(&capabilities, &rejection.refs, rejection.reason)?;
            let content_type = HeaderValue::from_static("application/x-git-receive-pack-result");
            return receive_response(StatusCode::OK, content_type, reply);
        }
        Err(publish::PublishError::Failed(error)) => return Err(error),
    }
    ref_guard.ensure_active()?;
    snapshot_lease.ensure_active()?;
    transfer_authorized(&state, Some(&actor), None, None, &repo, true).await.map_err(Error::internal)?;
    state.transfer_metrics.record_success();
    receive_response(status, content_type, reply)
}

fn receive_response(status: StatusCode, content_type: HeaderValue, reply: Vec<u8>) -> Result<Response<Body>, Error> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CACHE_CONTROL, "no-store")
        .header("x-content-type-options", "nosniff")
        .header("x-rootyard-write-policy", "fast-forward-only")
        .body(Body::from(reply))
        .map_err(Error::internal)
}

async fn owner_id(state: &AppState, repo: &Repository) -> Result<uuid::Uuid, Error> {
    let client = state.pool.get().await.map_err(Error::internal)?;
    client
        .query_one(
            "SELECT owner_id FROM repositories WHERE id=$1 AND storage_generation=$2 \
        AND storage_backend='pando' AND state='ready' AND transition_state='stable'",
            &[&repo.id, &repo.storage_generation],
        )
        .await
        .map_err(Error::internal)
        .map(|row| row.get(0))
}

#[allow(clippy::too_many_arguments)]
async fn run_backend(
    state: &AppState,
    parts: &Parts,
    input: receive::PreparedInput,
    actor: &Identity,
    repo: &Repository,
    path: &std::path::Path,
    lease: &storage::read_leases::Lease,
    deadline: Instant,
) -> Result<(StatusCode, HeaderValue, Vec<u8>), Error> {
    let project_root = path.parent().ok_or_else(Error::bad_request)?;
    let repository_dir = path.file_name().and_then(|s| s.to_str()).ok_or_else(Error::bad_request)?;
    let mut cmd = state.storage.git(&state.config);
    cmd.arg("-c")
        .arg("core.hooksPath=/dev/null")
        .arg("-c")
        .arg("http.receivepack=true")
        .arg("http-backend")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_PROJECT_ROOT", project_root)
        .env("PATH_INFO", format!("/{repository_dir}/git-receive-pack"))
        .env("GIT_HTTP_EXPORT_ALL", "1")
        .env("REQUEST_METHOD", "POST")
        .env("QUERY_STRING", "")
        .env("REMOTE_USER", &actor.username)
        .env("REMOTE_ADDR", "127.0.0.1")
        .env("GIT_HTTP_MAX_REQUEST_BUFFER", "10485760")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let gzipped = input.gzipped;
    if let Some(value) = parts.headers.get(header::CONTENT_TYPE) {
        cmd.env("CONTENT_TYPE", value.to_str().map_err(|_| Error::bad_request())?);
    }
    if let Some(value) = parts.headers.get(header::CONTENT_LENGTH).filter(|_| !gzipped) {
        cmd.env("CONTENT_LENGTH", value.to_str().map_err(|_| Error::bad_request())?);
    }
    if let Some(value) = parts.headers.get("git-protocol") {
        cmd.env("GIT_PROTOCOL", value.to_str().map_err(|_| Error::bad_request())?);
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
                let value = libc::rlimit { rlim_cur: limit, rlim_max: limit };
                if libc::setrlimit(resource, &value) == -1 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn().map_err(Error::internal)?;
    let pid = child.id().ok_or_else(Error::bad_request)? as i32;
    let stdin = child.stdin.take().ok_or_else(Error::bad_request)?;
    let stdout = child.stdout.take().ok_or_else(Error::bad_request)?;
    let mut stderr = child.stderr.take().ok_or_else(Error::bad_request)?;
    let input = tokio::spawn(receive::write_input(input, stdin, state.config.max_request_bytes));
    let stderr = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while matches!(stderr.read(&mut buf).await,Ok(n) if n>0) {}
    });
    let mut process = Process { child, input: Some(input), stderr, pid };
    let mut stdout = BufReader::with_capacity(16 * 1024, stdout);
    let result = tokio::time::timeout_at(deadline, async {
        let (status, content_type) = read_headers(&mut stdout).await?;
        let mut reply = Vec::new();
        let max_reply = state.config.max_output_bytes.min(MAX_RECEIVE_REPLY);
        let mut buf = [0u8; 32 * 1024];
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            let n = tokio::select! {
                value = stdout.read(&mut buf) => value?,
                _ = tick.tick() => {
                    ref_check(state,actor,repo,lease).await?;
                    continue;
                }
            };
            if n == 0 {
                break;
            }
            ref_check(state, actor, repo, lease).await?;
            if reply.len() as u64 + n as u64 > max_reply {
                return Err(io::Error::other("Pando receive response exceeded bound"));
            }
            reply.extend_from_slice(&buf[..n]);
        }
        if let Some(input) = process.input.take() {
            input.await.map_err(io::Error::other)??;
        }
        let exit = process.finish().await?;
        if !exit.success() {
            return Err(io::Error::other("Pando native receive failed"));
        }
        ref_check(state, actor, repo, lease).await?;
        Ok::<_, io::Error>((status, content_type, reply))
    })
    .await;
    process.stop().await;
    match result {
        Ok(Ok(reply)) => Ok(reply),
        Ok(Err(error)) => Err(Error::internal(error)),
        Err(_) => Err(Error::timeout()),
    }
}

async fn ref_check(
    state: &AppState,
    actor: &Identity,
    repo: &Repository,
    lease: &storage::read_leases::Lease,
) -> io::Result<()> {
    lease.ensure_active().map_err(|_| io::Error::other("Pando read lease lost"))?;
    transfer_authorized(state, Some(actor), None, None, repo, true).await
}
