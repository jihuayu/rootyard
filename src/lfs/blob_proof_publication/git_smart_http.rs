//! Git Smart HTTP (`http-backend` CGI) & internal pre-receive decision hook (`Refs #145`).

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::Path as FsPath;
use std::process::Stdio;
use std::sync::Arc;

use async_compression::tokio::bufread::GzipDecoder;
use axum::{
    Json,
    body::{Body, Bytes},
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::Response,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use uuid::Uuid;

use super::attestation::{LfsPushAttestationRequest, attest_and_authorize_push};
use super::authz::LfsPrincipal;
use super::http_router::{LfsBlobProofService, lfs_err_response, lfs_json_response};
use super::transfer::LfsTransferContext;
use super::types::{LfsBlobError, LfsProofRejectCode, LfsRefUpdateSpec};

const MAX_GIT_DECOMPRESSED_BYTES: usize = 64 * 1024 * 1024;

pub(super) struct GitBackendCall<'a> {
    pub bare_git_dir: &'a str,
    pub method: &'a str,
    pub endpoint: &'a str,
    pub query: &'a str,
    pub remote_user: &'a str,
    pub headers: &'a HeaderMap,
    pub extra_envs: &'a [(&'a str, String)],
    pub stdin_payload: Vec<u8>,
}

async fn decode_maybe_gzip(headers: &HeaderMap, raw: Bytes) -> Result<Vec<u8>, LfsBlobError> {
    let is_gzip = headers
        .get(header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("gzip"));
    if !is_gzip {
        if raw.len() > MAX_GIT_DECOMPRESSED_BYTES {
            return Err(LfsBlobError::new(LfsProofRejectCode::InvalidInput, "git request body exceeded hard cap"));
        }
        return Ok(raw.to_vec());
    }
    let decoder = GzipDecoder::new(BufReader::new(raw.as_ref()));
    let mut out = Vec::new();
    decoder
        .take((MAX_GIT_DECOMPRESSED_BYTES + 1) as u64)
        .read_to_end(&mut out)
        .await
        .map_err(|e| LfsBlobError::new(LfsProofRejectCode::InvalidInput, format!("gzip decode: {e}")))?;
    if out.len() > MAX_GIT_DECOMPRESSED_BYTES {
        return Err(LfsBlobError::new(LfsProofRejectCode::InvalidInput, "decompressed git payload exceeded hard cap"));
    }
    Ok(out)
}

fn ensure_pre_receive_hook(bare_git_dir: &str) -> Result<(), LfsBlobError> {
    let hooks_dir = FsPath::new(bare_git_dir).join("hooks");
    std::fs::create_dir_all(&hooks_dir)
        .map_err(|e| LfsBlobError::new(LfsProofRejectCode::InvalidInput, e.to_string()))?;
    let hook_path = hooks_dir.join("pre-receive");
    let script = concat!(
        "#!/usr/bin/env python3\n",
        "import json, os, sys, urllib.error, urllib.request\n",
        "payload = json.dumps({\n",
        "    'secret': os.environ['ROOTYARD_LFS_HOOK_SECRET'],\n",
        "    'repository_id': os.environ['ROOTYARD_LFS_REPO_ID'],\n",
        "    'actor_id': os.environ['ROOTYARD_LFS_ACTOR_ID'],\n",
        "    'actor_username': os.environ['ROOTYARD_LFS_ACTOR_NAME'],\n",
        "    'operation_id': os.environ['ROOTYARD_LFS_OP_ID'],\n",
        "    'git_object_dir': os.environ.get('GIT_OBJECT_DIRECTORY') or None,\n",
        "    'git_alternate_object_dirs': os.environ.get('GIT_ALTERNATE_OBJECT_DIRECTORIES') or None,\n",
        "    'stdin_lines': sys.stdin.read(),\n",
        "}).encode('utf-8')\n",
        "req = urllib.request.Request(\n",
        "    os.environ['ROOTYARD_LFS_CALLBACK_URL'],\n",
        "    data=payload,\n",
        "    headers={'Content-Type': 'application/json', 'Connection': 'close'},\n",
        "    method='POST',\n",
        ")\n",
        "try:\n",
        "    with urllib.request.urlopen(req, timeout=25) as resp:\n",
        "        sys.exit(0 if resp.status == 200 else 1)\n",
        "except urllib.error.HTTPError as err:\n",
        "    sys.stderr.write(err.read().decode('utf-8', 'replace') + '\\n')\n",
        "    sys.exit(1)\n",
    );
    std::fs::write(&hook_path, script)
        .map_err(|e| LfsBlobError::new(LfsProofRejectCode::InvalidInput, e.to_string()))?;
    std::fs::set_permissions(&hook_path, std::fs::Permissions::from_mode(0o755))
        .map_err(|e| LfsBlobError::new(LfsProofRejectCode::InvalidInput, e.to_string()))?;
    Ok(())
}

async fn invoke_git_http_backend(call: GitBackendCall<'_>) -> Result<Response, LfsBlobError> {
    let bare = FsPath::new(call.bare_git_dir);
    let project_root = bare
        .parent()
        .ok_or_else(|| LfsBlobError::new(LfsProofRejectCode::InvalidInput, "bare_git_dir missing parent"))?;
    let repo_dir = bare
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| LfsBlobError::new(LfsProofRejectCode::InvalidInput, "bare_git_dir missing filename"))?;
    let mut cmd = tokio::process::Command::new("git");
    cmd.env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_PROJECT_ROOT", project_root)
        .env("PATH_INFO", format!("/{repo_dir}/{}", call.endpoint))
        .env("GIT_HTTP_EXPORT_ALL", "1")
        .env("REQUEST_METHOD", call.method)
        .env("QUERY_STRING", call.query)
        .env("REMOTE_USER", call.remote_user)
        .env("REMOTE_ADDR", "127.0.0.1")
        .env("GIT_HTTP_MAX_REQUEST_BUFFER", "10485760")
        .args(["-c", "http.receivepack=true", "http-backend"]);
    if let Some(ct) = call.headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()) {
        cmd.env("CONTENT_TYPE", ct);
    }
    if let Some(proto) = call.headers.get("Git-Protocol").and_then(|v| v.to_str().ok()) {
        cmd.env("GIT_PROTOCOL", proto).env("HTTP_GIT_PROTOCOL", proto);
    }
    for (k, v) in call.extra_envs {
        cmd.env(k, v);
    }
    cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true);
    let mut child = cmd
        .spawn()
        .map_err(|e| LfsBlobError::new(LfsProofRejectCode::InvalidInput, format!("git http-backend: {e}")))?;
    if let Some(mut stdin) = child.stdin.take() {
        let payload = call.stdin_payload;
        tokio::spawn(async move {
            let _ = stdin.write_all(&payload).await;
        });
    }
    let out = child
        .wait_with_output()
        .await
        .map_err(|e| LfsBlobError::new(LfsProofRejectCode::InvalidInput, e.to_string()))?;
    if !out.status.success() {
        return Err(LfsBlobError::new(
            LfsProofRejectCode::InvalidInput,
            format!("git http-backend failed: {}", String::from_utf8_lossy(&out.stderr)),
        ));
    }
    parse_cgi_response(&out.stdout)
}

fn parse_cgi_response(raw: &[u8]) -> Result<Response, LfsBlobError> {
    let (hdr_bytes, body) = if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
        (&raw[..pos], &raw[pos + 4..])
    } else if let Some(pos) = raw.windows(2).position(|w| w == b"\n\n") {
        (&raw[..pos], &raw[pos + 2..])
    } else {
        return Err(LfsBlobError::new(LfsProofRejectCode::InvalidInput, "malformed CGI output from git http-backend"));
    };
    let hdr_str = std::str::from_utf8(hdr_bytes)
        .map_err(|_| LfsBlobError::new(LfsProofRejectCode::InvalidInput, "non-UTF8 CGI headers"))?;
    let mut status = StatusCode::OK;
    let mut builder = Response::builder().header(header::CONNECTION, "close");
    for line in hdr_str.lines() {
        let line = line.trim_end_matches('\r');
        let Some((name, val)) = line.split_once(':') else {
            continue;
        };
        let val = val.trim();
        if name.eq_ignore_ascii_case("status") {
            if let Some(code_str) = val.split_whitespace().next()
                && let Ok(code) = code_str.parse::<u16>()
                && let Ok(sc) = StatusCode::from_u16(code)
            {
                status = sc;
            }
        } else {
            builder = builder.header(name.trim(), val);
        }
    }
    builder
        .status(status)
        .body(Body::from(body.to_vec()))
        .map_err(|e| LfsBlobError::new(LfsProofRejectCode::InvalidInput, e.to_string()))
}

pub(super) async fn handle_git_info_refs(
    State(svc): State<Arc<LfsBlobProofService>>,
    Path((owner, repo)): Path<(String, String)>,
    Query(q): Query<BTreeMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let Some(service) = q.get("service").map(String::as_str) else {
        return lfs_err_response(LfsBlobError::new(LfsProofRejectCode::InvalidInput, "missing service query"));
    };
    let write = match service {
        "git-upload-pack" => false,
        "git-receive-pack" => true,
        _ => return lfs_err_response(LfsBlobError::new(LfsProofRejectCode::InvalidInput, "invalid git service")),
    };
    let (_, _, realm, access, _) = match svc.auth_repo(&headers, &owner, &repo, write).await {
        Ok(t) => t,
        Err(e) => return lfs_err_response(e),
    };
    let qs = format!("service={service}");
    let call = GitBackendCall {
        bare_git_dir: &realm.bare_git_dir,
        method: "GET",
        endpoint: "info/refs",
        query: &qs,
        remote_user: &access.actor_username,
        headers: &headers,
        extra_envs: &[],
        stdin_payload: Vec::new(),
    };
    match invoke_git_http_backend(call).await {
        Ok(r) => r,
        Err(e) => lfs_err_response(e),
    }
}

pub(super) async fn handle_git_upload_pack(
    State(svc): State<Arc<LfsBlobProofService>>,
    Path((owner, repo)): Path<(String, String)>,
    headers: HeaderMap,
    raw: Bytes,
) -> Response {
    let (_, _, realm, access, _) = match svc.auth_repo(&headers, &owner, &repo, false).await {
        Ok(t) => t,
        Err(e) => return lfs_err_response(e),
    };
    let input = match decode_maybe_gzip(&headers, raw).await {
        Ok(b) => b,
        Err(e) => return lfs_err_response(e),
    };
    let call = GitBackendCall {
        bare_git_dir: &realm.bare_git_dir,
        method: "POST",
        endpoint: "git-upload-pack",
        query: "",
        remote_user: &access.actor_username,
        headers: &headers,
        extra_envs: &[],
        stdin_payload: input,
    };
    match invoke_git_http_backend(call).await {
        Ok(r) => r,
        Err(e) => lfs_err_response(e),
    }
}

pub(super) async fn handle_git_receive_pack(
    State(svc): State<Arc<LfsBlobProofService>>,
    Path((owner, repo)): Path<(String, String)>,
    headers: HeaderMap,
    raw: Bytes,
) -> Response {
    let (_, _, realm, access, _) = match svc.auth_repo(&headers, &owner, &repo, true).await {
        Ok(t) => t,
        Err(e) => return lfs_err_response(e),
    };
    if let Err(e) = ensure_pre_receive_hook(&realm.bare_git_dir) {
        return lfs_err_response(e);
    }
    let input = match decode_maybe_gzip(&headers, raw).await {
        Ok(b) => b,
        Err(e) => return lfs_err_response(e),
    };
    let op_id = headers
        .get("X-Rootyard-Operation-Id")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| Uuid::parse_str(s).ok())
        .unwrap_or_else(Uuid::new_v4);
    let cb_url = format!("{}/_internal/lfs-pre-receive", svc.base_url().trim_end_matches('/'));
    let envs = [
        ("ROOTYARD_LFS_HOOK_SECRET", svc.internal_secret().to_owned()),
        ("ROOTYARD_LFS_CALLBACK_URL", cb_url),
        ("ROOTYARD_LFS_REPO_ID", realm.repository_id.to_string()),
        ("ROOTYARD_LFS_ACTOR_ID", access.actor_id.to_string()),
        ("ROOTYARD_LFS_ACTOR_NAME", access.actor_username.clone()),
        ("ROOTYARD_LFS_OP_ID", op_id.to_string()),
    ];
    let call = GitBackendCall {
        bare_git_dir: &realm.bare_git_dir,
        method: "POST",
        endpoint: "git-receive-pack",
        query: "",
        remote_user: &access.actor_username,
        headers: &headers,
        extra_envs: &envs,
        stdin_payload: input,
    };
    match invoke_git_http_backend(call).await {
        Ok(r) => r,
        Err(e) => lfs_err_response(e),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct InternalPreReceivePayload {
    secret: String,
    repository_id: Uuid,
    actor_id: Uuid,
    actor_username: String,
    operation_id: Uuid,
    git_object_dir: Option<String>,
    git_alternate_object_dirs: Option<String>,
    stdin_lines: String,
}

pub(super) async fn handle_internal_pre_receive(
    State(svc): State<Arc<LfsBlobProofService>>,
    Json(payload): Json<InternalPreReceivePayload>,
) -> Response {
    if Sha256::digest(payload.secret.as_bytes()) != Sha256::digest(svc.internal_secret().as_bytes()) {
        return lfs_err_response(LfsBlobError::new(LfsProofRejectCode::UnauthorizedCollaborator, "bad hook secret"));
    }
    let gate = svc.current_gate();
    let realm = match svc.pg().load_repo_by_id(payload.repository_id).await {
        Ok(r) => r,
        Err(e) => return lfs_err_response(e),
    };
    let dummy_principal = LfsPrincipal {
        actor_id: payload.actor_id,
        username: payload.actor_username,
        secret_sha256: String::new(),
    };
    let access = match svc.pg().authorize_repo_access(&realm, &dummy_principal, true, false).await {
        Ok(a) => a,
        Err(e) => return lfs_err_response(e),
    };
    let mut updates = Vec::new();
    for line in payload.stdin_lines.lines().filter(|l| !l.trim().is_empty()) {
        let mut p = line.split_whitespace();
        let (Some(old_oid), Some(new_oid), Some(ref_name)) = (p.next(), p.next(), p.next()) else {
            return lfs_err_response(LfsBlobError::new(LfsProofRejectCode::InvalidInput, "bad pre-receive line"));
        };
        updates.push(LfsRefUpdateSpec {
            ref_name: ref_name.to_owned(),
            old_oid: old_oid.to_owned(),
            new_oid: new_oid.to_owned(),
        });
    }
    let ctx = LfsTransferContext {
        gate: &gate,
        pg: svc.pg(),
        realm: &realm,
        access: &access,
        scratch_dir: svc.scratch_dir(),
        timeout: svc.timeout(),
    };
    let req = LfsPushAttestationRequest {
        operation_id: payload.operation_id,
        updates,
        git_object_dir: payload.git_object_dir,
        git_alternate_object_dirs: payload.git_alternate_object_dirs,
    };
    match attest_and_authorize_push(&ctx, &req).await {
        Ok(outcome) => lfs_json_response(StatusCode::OK, outcome.attestation()),
        Err(e) => lfs_err_response(e),
    }
}
