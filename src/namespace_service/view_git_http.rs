//! Read-only Smart HTTP transport (`/git/views/{id}.git/...`) for projected Git Views.
use super::views;
use crate::{
    AppState, Error, auth, db::Identity, members::models::Role, storage::read_leases, token_scopes::RepoAction,
};
use async_compression::tokio::bufread::GzipDecoder;
use axum::{
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, HeaderName, StatusCode, Uri, header},
    response::IntoResponse,
};
use futures_util::StreamExt;
use std::{
    fs::{self, OpenOptions},
    io::{self, Seek, SeekFrom},
    path::{Path as FsPath, PathBuf},
    process::Stdio,
    sync::Arc,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio_util::io::StreamReader;
use uuid::Uuid;

pub const UPLOAD_BODY_LIMIT: usize = 10 * 1024 * 1024;
const ADVERTISE_LIMIT: usize = 4 * 1024 * 1024;
const UPLOAD_RESULT_CAP: usize = 64 * 1024 * 1024;

#[rustfmt::skip]
#[path = "s4_git_view_http.rs"]
mod s4_git_view_http;

#[derive(Debug)]
struct TempFileGuard(Option<PathBuf>);
impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = fs::remove_file(path);
        }
    }
}

pub(super) fn parse_view_git_id(view_git: &str) -> Result<Uuid, Error> {
    let raw = view_git.strip_suffix(".git").ok_or_else(Error::not_found)?;
    let id = Uuid::parse_str(raw).map_err(|_| Error::not_found())?;
    if id.is_nil() {
        return Err(Error::not_found());
    }
    Ok(id)
}

fn validate_git_protocol(headers: &HeaderMap) -> Result<Option<String>, Error> {
    let Some(value) = headers.get("git-protocol") else {
        return Ok(None);
    };
    let text = value.to_str().map_err(|_| Error::bad_request())?;
    if !matches!(text, "version=0" | "version=1" | "version=2") {
        return Err(Error::bad_request());
    }
    Ok(Some(text.to_owned()))
}

fn validate_upload_headers(headers: &HeaderMap, max_bytes: u64) -> Result<(bool, Option<String>), Error> {
    if headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()) != Some("application/x-git-upload-pack-request")
    {
        return Err(Error(StatusCode::UNSUPPORTED_MEDIA_TYPE, "invalid Git content type"));
    }
    let gzipped = match headers.get(header::CONTENT_ENCODING) {
        None => false,
        Some(v) if v == "identity" => false,
        Some(v) if v == "gzip" || v == "x-gzip" => true,
        _ => return Err(Error(StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported request encoding")),
    };
    if let Some(value) = headers.get(header::CONTENT_LENGTH) {
        let size = value.to_str().ok().and_then(|v| v.parse::<u64>().ok()).ok_or_else(Error::bad_request)?;
        if size > max_bytes {
            return Err(Error(StatusCode::PAYLOAD_TOO_LARGE, "request size limit exceeded"));
        }
    }
    let protocol = validate_git_protocol(headers)?;
    Ok((gzipped, protocol))
}

fn service_prefix(service: &str) -> Vec<u8> {
    let line = format!("# service={service}\n");
    let mut bytes = format!("{:04x}", line.len() + 4).into_bytes();
    bytes.extend_from_slice(line.as_bytes());
    bytes.extend_from_slice(b"0000");
    bytes
}

fn git_dir_for_view(state: &AppState, id: Uuid) -> Result<PathBuf, Error> {
    let root = views::projection_root(state).join(id.to_string());
    let dot_git = root.join(".git");
    if dot_git.is_dir() {
        return Ok(dot_git);
    }
    if root.join("HEAD").is_file() {
        return Ok(root);
    }
    Err(Error::not_found())
}

async fn authorize_view_git_read(
    state: &AppState,
    actor: &Identity,
    id: Uuid,
) -> Result<(views::View, PathBuf), Error> {
    let view = views::load_for_actor(state, actor, id).await?;
    auth::verify_active(&state.pool, actor, view.repository_id, RepoAction::ContentsRead, Role::Read).await?;
    let git_dir = git_dir_for_view(state, id)?;
    Ok((view, git_dir))
}

fn create_temp_request_file(root: &FsPath, id: Uuid) -> Result<(std::fs::File, TempFileGuard), Error> {
    let tmp_dir = root.join("tmp");
    fs::create_dir_all(&tmp_dir).map_err(Error::internal)?;
    let path = tmp_dir.join(format!("upload-{id}-{}.bin", Uuid::new_v4()));
    let mut opts = OpenOptions::new();
    opts.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = opts.open(&path).map_err(Error::internal)?;
    Ok((file, TempFileGuard(Some(path))))
}

fn remaining_timeout(deadline: tokio::time::Instant) -> Result<std::time::Duration, Error> {
    deadline.checked_duration_since(tokio::time::Instant::now()).filter(|d| !d.is_zero()).ok_or_else(Error::timeout)
}

async fn run_bounded<T, Fut>(deadline: tokio::time::Instant, fut: Fut) -> Result<T, Error>
where
    Fut: std::future::Future<Output = Result<T, Error>>,
{
    tokio::time::timeout_at(deadline, fut).await.map_err(|_| Error::timeout())?
}

async fn spool_body_to_temp(
    root: &FsPath,
    id: Uuid,
    body: Body,
    gzipped: bool,
    max_bytes: u64,
    deadline: tokio::time::Instant,
) -> Result<(std::fs::File, TempFileGuard), Error> {
    let (std_file, guard) = create_temp_request_file(root, id)?;
    let read_result = tokio::time::timeout_at(deadline, async {
        let mut file = tokio::fs::File::from_std(std_file);
        let mut wire_bytes = 0u64;
        let stream = body.into_data_stream().map(move |chunk| {
            let chunk = chunk.map_err(io::Error::other)?;
            wire_bytes = wire_bytes.saturating_add(chunk.len() as u64);
            if wire_bytes > max_bytes {
                return Err(io::Error::new(io::ErrorKind::FileTooLarge, "request wire size limit exceeded"));
            }
            Ok(chunk)
        });
        let reader = StreamReader::new(stream);
        let mut reader: std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send>> = if gzipped {
            let mut decoder = GzipDecoder::new(BufReader::new(reader));
            decoder.multiple_members(true);
            Box::pin(decoder)
        } else {
            Box::pin(reader)
        };
        let mut decoded = 0u64;
        let mut buf = [0u8; 32 * 1024];
        loop {
            let n = reader.read(&mut buf).await.map_err(|err| {
                if err.kind() == io::ErrorKind::FileTooLarge {
                    Error(StatusCode::PAYLOAD_TOO_LARGE, "request size limit exceeded")
                } else {
                    Error::bad_request()
                }
            })?;
            if n == 0 {
                break;
            }
            decoded = decoded.saturating_add(n as u64);
            if decoded > max_bytes {
                return Err(Error(StatusCode::PAYLOAD_TOO_LARGE, "request size limit exceeded"));
            }
            file.write_all(&buf[..n]).await.map_err(Error::internal)?;
        }
        if decoded == 0 {
            return Err(Error::bad_request());
        }
        file.flush().await.map_err(Error::internal)?;
        let mut std_file = file.into_std().await;
        std_file.seek(SeekFrom::Start(0)).map_err(Error::internal)?;
        Ok(std_file)
    })
    .await;
    match read_result {
        Ok(Ok(std_file)) => Ok((std_file, guard)),
        Ok(Err(err)) => Err(err),
        Err(_) => Err(Error::timeout()),
    }
}

pub async fn info_refs(
    State(state): State<Arc<AppState>>,
    Path(view_git): Path<String>,
    uri: Uri,
    headers: HeaderMap,
) -> Result<axum::response::Response, Error> {
    let id = parse_view_git_id(&view_git)?;
    match uri.query() {
        Some("service=git-upload-pack") => {}
        Some("service=git-receive-pack") => {
            let actor = auth::authenticate(&state.pool, &headers).await?;
            let view = views::load_for_actor(&state, &actor, id).await?;
            auth::verify_active(&state.pool, &actor, view.repository_id, RepoAction::ContentsRead, Role::Read).await?;
            if views::s4_git_view::is_refstore(&state, view.repository_id).await? {
                s4_git_view_http::verify_active_binding(&state, &view, id).await?;
            } else {
                let _ = git_dir_for_view(&state, id)?;
            }
            return Err(Error(StatusCode::FORBIDDEN, "projected Git views are read-only"));
        }
        _ => return Err(Error::bad_request()),
    }
    let protocol = validate_git_protocol(&headers)?;
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let view = views::load_for_actor(&state, &actor, id).await?;
    auth::verify_active(&state.pool, &actor, view.repository_id, RepoAction::ContentsRead, Role::Read).await?;
    if views::s4_git_view::is_refstore(&state, view.repository_id).await? {
        return s4_git_view_http::info_refs(&state, &actor, &view, protocol.as_deref()).await;
    }
    let git_dir = git_dir_for_view(&state, id)?;
    let _slot = state
        .git_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| Error(StatusCode::SERVICE_UNAVAILABLE, "Git capacity exhausted; retry later"))?;
    let deadline = tokio::time::Instant::now() + state.config.git_timeout;
    let advertised = run_bounded(deadline, async {
        let source_lease = read_leases::shared(&state.pool, view.repository_id, deadline).await?;
        let _local = tokio::time::timeout_at(deadline, state.storage.read_snapshot_lock(view.repository_id))
            .await
            .map_err(|_| Error::timeout())?;
        source_lease.ensure_active()?;
        let _ = authorize_view_git_read(&state, &actor, id).await?;
        let mut cmd = state.storage.git(&state.config);
        cmd.args(["-c", "core.hooksPath=/dev/null", "--no-replace-objects"]);
        if let Some(proto) = protocol.as_deref() {
            cmd.env("GIT_PROTOCOL", proto);
        }
        cmd.args(["upload-pack", "--stateless-rpc", "--advertise-refs"]).arg(&git_dir);
        let advertised = source_lease
            .guard(crate::git_http::collect_git_output(cmd, ADVERTISE_LIMIT, remaining_timeout(deadline)?))
            .await?
            .map_err(|_| {
                if tokio::time::Instant::now() >= deadline {
                    Error::timeout()
                } else {
                    Error(StatusCode::SERVICE_UNAVAILABLE, "projected Git view unavailable")
                }
            })?;
        source_lease.ensure_active()?;
        let _ = authorize_view_git_read(&state, &actor, id).await?;
        Ok(advertised)
    })
    .await?;
    let mut body = service_prefix("git-upload-pack");
    body.extend_from_slice(&advertised);
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/x-git-upload-pack-advertisement"),
            (header::CACHE_CONTROL, "no-store"),
            (HeaderName::from_static("x-content-type-options"), "nosniff"),
        ],
        body,
    )
        .into_response())
}

pub async fn upload_pack(
    State(state): State<Arc<AppState>>,
    Path(view_git): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Result<axum::response::Response, Error> {
    let id = parse_view_git_id(&view_git)?;
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let view = views::load_for_actor(&state, &actor, id).await?;
    auth::verify_active(&state.pool, &actor, view.repository_id, RepoAction::ContentsRead, Role::Read).await?;
    if views::s4_git_view::is_refstore(&state, view.repository_id).await? {
        return s4_git_view_http::upload_pack(&state, &actor, &view, &headers, body).await;
    }
    let git_dir = git_dir_for_view(&state, id)?;
    let max_req = state.config.max_request_bytes.min(UPLOAD_BODY_LIMIT as u64);
    let (gzipped, protocol) = validate_upload_headers(&headers, max_req)?;
    let _slot = state
        .git_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| Error(StatusCode::SERVICE_UNAVAILABLE, "Git capacity exhausted; retry later"))?;
    let deadline = tokio::time::Instant::now() + state.config.git_timeout;
    let projection_root = views::projection_root(&state);
    let pack = run_bounded(deadline, async {
        let (req_file, _tmp_guard) = spool_body_to_temp(&projection_root, id, body, gzipped, max_req, deadline).await?;
        let source_lease = read_leases::shared(&state.pool, view.repository_id, deadline).await?;
        let _local = tokio::time::timeout_at(deadline, state.storage.read_snapshot_lock(view.repository_id))
            .await
            .map_err(|_| Error::timeout())?;
        source_lease.ensure_active()?;
        let _ = authorize_view_git_read(&state, &actor, id).await?;
        let mut cmd = state.storage.git(&state.config);
        cmd.args(["-c", "core.hooksPath=/dev/null", "--no-replace-objects"]);
        if let Some(proto) = protocol.as_deref() {
            cmd.env("GIT_PROTOCOL", proto);
        }
        cmd.args(["upload-pack", "--stateless-rpc"]).arg(&git_dir);
        let max_out =
            usize::try_from(state.config.max_output_bytes).unwrap_or(UPLOAD_RESULT_CAP).min(UPLOAD_RESULT_CAP);
        let pack = source_lease
            .guard(crate::git_http::collect_git_output_input(
                cmd,
                max_out,
                remaining_timeout(deadline)?,
                Stdio::from(req_file),
            ))
            .await?
            .map_err(|_| {
                if tokio::time::Instant::now() >= deadline {
                    Error::timeout()
                } else {
                    Error(StatusCode::BAD_REQUEST, "invalid or unauthorized Git object request")
                }
            })?;
        if pack.get(4..).is_some_and(|rest| rest.starts_with(b"ERR ")) {
            return Err(Error(StatusCode::BAD_REQUEST, "invalid or unauthorized Git object request"));
        }
        source_lease.ensure_active()?;
        let _ = authorize_view_git_read(&state, &actor, id).await?;
        Ok(pack)
    })
    .await?;
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/x-git-upload-pack-result"),
            (header::CACHE_CONTROL, "no-store"),
            (HeaderName::from_static("x-content-type-options"), "nosniff"),
        ],
        pack,
    )
        .into_response())
}

pub async fn reject_receive_pack(
    State(state): State<Arc<AppState>>,
    Path(view_git): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, Error> {
    let id = parse_view_git_id(&view_git)?;
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let view = views::load_for_actor(&state, &actor, id).await?;
    auth::verify_active(&state.pool, &actor, view.repository_id, RepoAction::ContentsRead, Role::Read).await?;
    if views::s4_git_view::is_refstore(&state, view.repository_id).await? {
        s4_git_view_http::verify_active_binding(&state, &view, id).await?;
        return Err(Error(StatusCode::FORBIDDEN, "projected Git views are read-only"));
    }
    let _ = git_dir_for_view(&state, id)?;
    Err(Error(StatusCode::FORBIDDEN, "projected Git views are read-only"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_view_git_suffix_and_rejects_invalid_paths() {
        let id = Uuid::new_v4();
        assert_eq!(parse_view_git_id(&format!("{id}.git")).unwrap(), id);
        for bad in ["", ".git", &id.to_string(), &format!("{}.git", Uuid::nil()), "not-a-uuid.git", "../other.git"] {
            assert_eq!(parse_view_git_id(bad).unwrap_err().0, StatusCode::NOT_FOUND);
        }
    }

    #[test]
    fn formats_smart_http_service_prefix_and_validates_headers() {
        assert_eq!(service_prefix("git-upload-pack"), b"001e# service=git-upload-pack\n0000");

        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, "application/x-git-upload-pack-request".parse().unwrap());
        headers.insert(header::CONTENT_ENCODING, "gzip".parse().unwrap());
        headers.insert("git-protocol", "version=2".parse().unwrap());
        assert_eq!(validate_upload_headers(&headers, 1024).unwrap(), (true, Some("version=2".to_owned())));

        headers.insert("git-protocol", "version=9".parse().unwrap());
        assert_eq!(validate_upload_headers(&headers, 1024).unwrap_err().0, StatusCode::BAD_REQUEST);

        headers.insert("git-protocol", "version=2".parse().unwrap());
        headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
        assert_eq!(validate_upload_headers(&headers, 1024).unwrap_err().0, StatusCode::UNSUPPORTED_MEDIA_TYPE);

        headers.insert(header::CONTENT_TYPE, "application/x-git-upload-pack-request".parse().unwrap());
        headers.insert(header::CONTENT_LENGTH, "4096".parse().unwrap());
        assert_eq!(validate_upload_headers(&headers, 1024).unwrap_err().0, StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn stalled_and_cancelled_upload_bodies_timeout_and_remove_temp_files() {
        let tmp = tempfile::tempdir().unwrap();
        let id = Uuid::new_v4();
        let stalled = Body::from_stream(futures_util::stream::pending::<Result<bytes::Bytes, io::Error>>());
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(80);
        let err = spool_body_to_temp(tmp.path(), id, stalled, false, 1024, deadline).await.unwrap_err();
        assert_eq!(err.0, StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(fs::read_dir(tmp.path().join("tmp")).unwrap().count(), 0);
        assert_eq!(remaining_timeout(deadline).unwrap_err().0, StatusCode::GATEWAY_TIMEOUT);

        let partial = futures_util::stream::iter([Ok::<_, io::Error>(bytes::Bytes::from_static(b"0009want "))])
            .chain(futures_util::stream::pending());
        let cancelled = Body::from_stream(partial);
        let long_deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        tokio::select! {
            _ = spool_body_to_temp(tmp.path(), id, cancelled, false, 1024, long_deadline) => {
                panic!("stalled partial body unexpectedly finished");
            }
            () = tokio::time::sleep(std::time::Duration::from_millis(40)) => {}
        }
        assert_eq!(fs::read_dir(tmp.path().join("tmp")).unwrap().count(), 0);

        let slots = Arc::new(tokio::sync::Semaphore::new(1));
        let permit = slots.clone().try_acquire_owned().unwrap();
        let slot_deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(50);
        let slot_res: Result<(), Error> = run_bounded(slot_deadline, async move {
            let _held = permit;
            std::future::pending::<Result<(), Error>>().await
        })
        .await;
        assert_eq!(slot_res.unwrap_err().0, StatusCode::GATEWAY_TIMEOUT);
        assert!(slots.clone().try_acquire_owned().is_ok());
    }
}
