//! Smart-HTTP Git harness driving production `rootyard::lfs::routes()` and
//! `rootyard::browse::policy::validate_hook` (`Refs #145`).

use std::path::{Path as FsPath, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    Router,
    body::{Body, Bytes},
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use rootyard::{
    AppState, auth,
    journal::{self, RefChange},
    lfs::blob_proof_publication::{LfsBlobError, PgLfsBlobStore, active_blob_gate, extract_stable_operation_id},
    token_scopes::RepoAction,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::process::Command;
use uuid::Uuid;

use super::{RealHookInput, run_real_validate_hook};

pub fn production_s4_test_router(state: Arc<AppState>) -> Router {
    Router::new()
        .merge(rootyard::lfs::routes())
        .merge(rootyard::repositories::routes())
        .merge(rootyard::organizations::routes())
        .merge(rootyard::members::routes())
        .fallback(smart_git_fallback)
        .with_state(state)
}

fn json_err(err: LfsBlobError) -> Response {
    let status = err.code.http_status();
    let mut res =
        (status, axum::Json(json!({ "code": err.code.as_str(), "error": err.code.as_str(), "message": err.message })))
            .into_response();
    res.headers_mut().insert(header::CONNECTION, "close".parse().unwrap());
    if status == StatusCode::UNAUTHORIZED {
        res.headers_mut()
            .insert(header::WWW_AUTHENTICATE, "Basic realm=\"Rootyard\", charset=\"UTF-8\"".parse().unwrap());
    }
    res
}

fn parse_git_route(path: &str) -> Option<(&str, &str, &str)> {
    let trimmed = path.trim_start_matches('/');
    let trimmed = trimmed.strip_prefix("git/").unwrap_or(trimmed);
    let (owner, rest) = trimmed.split_once('/')?;
    let (repo_seg, tail) = rest.split_once('/')?;
    let repo = repo_seg.strip_suffix(".git").unwrap_or(repo_seg);
    if matches!(tail, "info/refs" | "git-upload-pack" | "git-receive-pack") { Some((owner, repo, tail)) } else { None }
}

fn pkt_line(data: &[u8]) -> Vec<u8> {
    let mut out = format!("{:04x}", data.len() + 4).into_bytes();
    out.extend_from_slice(data);
    out
}

#[derive(Deserialize)]
struct HookWireIn {
    git_object_dir: Option<String>,
    git_alternate_object_dirs: Option<String>,
    stdin: String,
}

#[derive(Serialize)]
struct HookWireOut {
    ok: bool,
    message: String,
}

fn install_loopback_pre_receive(bare_dir: &FsPath, port: u16) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let hooks_dir = bare_dir.join("hooks");
    std::fs::create_dir_all(&hooks_dir)?;
    let hook_path = hooks_dir.join("pre-receive");
    let script = format!(
        "#!/usr/bin/env python3\n\
import json, os, socket, sys\n\
payload = json.dumps({{\n\
  'git_object_dir': os.environ.get('GIT_OBJECT_DIRECTORY'),\n\
  'git_alternate_object_dirs': os.environ.get('GIT_ALTERNATE_OBJECT_DIRECTORIES'),\n\
  'stdin': sys.stdin.read(),\n\
}}).encode('utf-8')\n\
s = socket.create_connection(('127.0.0.1', {port}), timeout=25)\n\
s.sendall(payload)\n\
s.shutdown(socket.SHUT_WR)\n\
chunks = []\n\
while True:\n\
    b = s.recv(65536)\n\
    if not b:\n\
        break\n\
    chunks.append(b)\n\
s.close()\n\
res = json.loads(b''.join(chunks).decode('utf-8'))\n\
if not res.get('ok', False):\n\
    sys.stderr.write(res.get('message', 'pre-receive rejected') + '\\n')\n\
    sys.exit(1)\n\
sys.exit(0)\n"
    );
    std::fs::write(&hook_path, script)?;
    std::fs::set_permissions(&hook_path, std::fs::Permissions::from_mode(0o755))?;
    Ok(())
}

async fn smart_git_fallback(
    State(state): State<Arc<AppState>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, rootyard::Error> {
    let Some((owner, repo_name, tail)) = parse_git_route(uri.path()) else {
        return Err(rootyard::Error::not_found());
    };
    if let Some(gate) = active_blob_gate()
        && let Err(e) = gate.require_store()
    {
        return Ok(json_err(e));
    }
    let query_service = uri.query().unwrap_or("").split('&').find_map(|kv| kv.strip_prefix("service="));
    let service = match (method.clone(), tail, query_service) {
        (Method::GET, "info/refs", Some(svc @ ("git-upload-pack" | "git-receive-pack"))) => svc,
        (Method::POST, svc @ ("git-upload-pack" | "git-receive-pack"), _) => svc,
        _ => return Err(rootyard::Error::bad_request()),
    };
    let write = service == "git-receive-pack";
    let clean_headers = rootyard::lfs::handlers::sanitize_headers(&headers);
    let actor = auth::authenticate(&state.pool, &clean_headers).await?;
    if write {
        auth::writable(&actor)?;
    }

    let row = state
        .pool
        .get()
        .await
        .map_err(rootyard::Error::internal)?
        .query_opt(
            "SELECT r.id, r.owner_id, r.storage_generation
             FROM repositories r JOIN namespaces ns ON ns.id = r.owner_id
             WHERE ns.slug = $1 AND r.name = $2 AND r.deleted_at IS NULL",
            &[&owner, &repo_name],
        )
        .await
        .map_err(rootyard::Error::internal)?
        .ok_or_else(rootyard::Error::not_found)?;
    let repo_id: Uuid = row.get(0);
    let owner_id: Uuid = row.get(1);
    let storage_generation: i64 = row.get(2);

    let pg = PgLfsBlobStore::new(state.pool.clone());
    let realm = match pg.ensure_realm_for_repository(repo_id, &state.storage.root).await {
        Ok(r) => r,
        Err(e) => return Ok(json_err(e)),
    };
    if realm.owner_tenant_id != owner_id {
        return Err(rootyard::Error(StatusCode::CONFLICT, "repository identity changed"));
    }
    if let Err(e) = pg.resolve_authoritative_repo_access(&realm, actor.id, &actor.username, write, false).await {
        return Ok(json_err(e));
    }
    {
        let mut client = state.pool.get().await.map_err(rootyard::Error::internal)?;
        let tx = client.transaction().await.map_err(rootyard::Error::internal)?;
        auth::authorize_repo_with_role(
            &tx,
            &actor,
            owner,
            repo_name,
            if write { auth::Role::Write } else { auth::Role::Read },
            if write { RepoAction::ContentsWrite } else { RepoAction::ContentsRead },
        )
        .await?;
        auth::finish_tx(tx, &actor, false).await?;
    }

    let bare_dir: PathBuf = state.storage.repo_path(repo_id);
    if tail == "info/refs" {
        let sub = service.strip_prefix("git-").unwrap_or(service);
        let mut cmd = Command::new(&state.config.git);
        cmd.args([sub, "--stateless-rpc", "--advertise-refs"]).arg(&bare_dir);
        if let Some(proto) = headers.get("git-protocol").and_then(|v| v.to_str().ok()) {
            cmd.env("GIT_PROTOCOL", proto);
        }
        let out = cmd.output().await.map_err(rootyard::Error::internal)?;
        if !out.status.success() {
            return Err(rootyard::Error::internal("git advertise-refs failed"));
        }
        let mut wire = pkt_line(format!("# service={service}\n").as_bytes());
        wire.extend_from_slice(b"0000");
        wire.extend_from_slice(&out.stdout);
        return Ok((
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, format!("application/x-{service}-advertisement")),
                (header::CACHE_CONTROL, "no-cache".into()),
                (header::CONNECTION, "close".into()),
            ],
            Body::from(wire),
        )
            .into_response());
    }

    let explicit_op_id = match extract_stable_operation_id(&clean_headers) {
        Ok(opt) => opt,
        Err(e) => return Ok(json_err(e)),
    };

    let hook_task = if write {
        let listener = TcpListener::bind("127.0.0.1:0").await.map_err(rootyard::Error::internal)?;
        let port = listener.local_addr().map_err(rootyard::Error::internal)?.port();
        install_loopback_pre_receive(&bare_dir, port).map_err(rootyard::Error::internal)?;
        let st = Arc::clone(&state);
        let bdir = bare_dir.clone();
        let act = actor.clone();
        Some(tokio::spawn(async move {
            let Ok(Ok((mut sock, _))) = tokio::time::timeout(Duration::from_secs(25), listener.accept()).await else {
                return;
            };
            let mut raw = Vec::new();
            if sock.read_to_end(&mut raw).await.is_err() {
                return;
            }
            let Ok(wire_in) = serde_json::from_slice::<HookWireIn>(&raw) else {
                return;
            };
            let mut changes = Vec::new();
            for line in wire_in.stdin.lines().map(str::trim).filter(|l| !l.is_empty()) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() == 3 {
                    changes.push(RefChange {
                        old_oid: parts[0].to_owned(),
                        new_oid: parts[1].to_owned(),
                        ref_name: parts[2].to_owned(),
                    });
                }
            }
            let idem = explicit_op_id.map(|op_uuid| journal::IdempotencyIntent {
                key_sha256: op_uuid.to_string(),
                request_sha256: "0".repeat(64),
            });
            let op_res = journal::begin_ref_transaction(
                &st.storage.root,
                repo_id,
                act.id,
                act.username.clone(),
                act.token_id,
                storage_generation,
                idem,
            );
            let reply = match op_res {
                Ok(op) => {
                    let res = tokio::task::block_in_place(|| {
                        run_real_validate_hook(RealHookInput {
                            db_url: &st.config.database_url,
                            git_bin: &st.config.git,
                            git_dir: &bdir,
                            data_root: &st.storage.root,
                            git_obj_dir: wire_in.git_object_dir.as_deref(),
                            git_alt_dirs: wire_in.git_alternate_object_dirs.as_deref(),
                            op: &op,
                            changes: &changes,
                        })
                    });
                    let _ = journal::finish(&op);
                    match res {
                        Ok(()) => HookWireOut { ok: true, message: "ok".into() },
                        Err(e) => HookWireOut { ok: false, message: format!("{e:#}") },
                    }
                }
                Err(e) => HookWireOut { ok: false, message: format!("journal begin failed: {e:#}") },
            };
            if let Ok(resp_bytes) = serde_json::to_vec(&reply) {
                let _ = sock.write_all(&resp_bytes).await;
            }
        }))
    } else {
        None
    };

    let sub = service.strip_prefix("git-").unwrap_or(service);
    let mut cmd = Command::new(&state.config.git);
    cmd.args([sub, "--stateless-rpc"])
        .arg(&bare_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(proto) = headers.get("git-protocol").and_then(|v| v.to_str().ok()) {
        cmd.env("GIT_PROTOCOL", proto);
    }
    let mut child = cmd.spawn().map_err(rootyard::Error::internal)?;
    if let Some(mut sin) = child.stdin.take() {
        let _ = sin.write_all(&body).await;
    }
    let out = child.wait_with_output().await.map_err(rootyard::Error::internal)?;
    if let Some(h) = hook_task {
        h.abort();
    }
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, format!("application/x-{service}-result")),
            (header::CACHE_CONTROL, "no-cache".into()),
            (header::CONNECTION, "close".into()),
        ],
        Body::from(out.stdout),
    )
        .into_response())
}
