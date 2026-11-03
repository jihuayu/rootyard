use super::*;
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::State,
    http::{Request, Response, StatusCode, header},
    routing::any,
};
use std::io::Write;

#[derive(Clone)]
struct Server {
    config: Arc<Config>,
    slots: Arc<tokio::sync::Semaphore>,
}
fn reply(status: StatusCode, text: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(text.to_owned()))
        .unwrap()
}

pub(super) async fn serve(config: Arc<Config>) -> Result<()> {
    let version = String::from_utf8(config.git(&config.root, &["--version"], b"").await?)?;
    let numbers: Vec<u32> = version
        .split_whitespace()
        .nth(2)
        .unwrap_or("")
        .split('.')
        .take(2)
        .map(|n| n.parse().unwrap_or(0))
        .collect();
    ensure!(
        numbers.len() == 2 && (numbers[0], numbers[1]) >= (2, 43),
        "lab requires native Git 2.43 or newer for proc-receive"
    );
    let listen: std::net::SocketAddr = std::env::var("PANDO_LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:0".into())
        .parse()?;
    ensure!(
        listen.ip().is_loopback(),
        "lab server may only listen on loopback"
    );
    let listener = tokio::net::TcpListener::bind(listen).await?;
    println!("LISTEN http://{}", listener.local_addr()?);
    std::io::stdout().flush()?;
    let state = Server {
        config,
        slots: Arc::new(tokio::sync::Semaphore::new(8)),
    };
    axum::serve(
        listener,
        Router::new().fallback(any(handler)).with_state(state),
    )
    .await?;
    Ok(())
}

async fn handler(State(s): State<Server>, request: Request<Body>) -> Response<Body> {
    let Ok(_slot) = s.slots.clone().try_acquire_owned() else {
        return reply(StatusCode::SERVICE_UNAVAILABLE, "lab capacity reached");
    };
    match serve_git(&s.config, request).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("pando lab request failed: {e:#}");
            reply(StatusCode::SERVICE_UNAVAILABLE, "lab request failed closed")
        }
    }
}

async fn serve_git(config: &Config, request: Request<Body>) -> Result<Response<Body>> {
    let (parts, body) = request.into_parts();
    let principal = parts
        .headers
        .get("X-Pando-Principal")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if principal.is_empty() || principal.len() > 64 {
        return Ok(reply(
            StatusCode::UNAUTHORIZED,
            "synthetic principal required",
        ));
    }
    let path = parts.uri.path();
    let segments: Vec<_> = path.trim_start_matches('/').split('/').collect();
    let (token, repository, tail) = match segments.as_slice() {
        ["repos", repo, tail @ ..] => (None, *repo, tail.join("/")),
        ["snapshots", token, repo, tail @ ..] => {
            (Some(token.parse::<Uuid>()?), *repo, tail.join("/"))
        }
        _ => return Ok(reply(StatusCode::NOT_FOUND, "unknown route")),
    };
    let Some(id) = repository.strip_suffix(".git") else {
        return Ok(reply(StatusCode::NOT_FOUND, "unknown repository"));
    };
    let repo: Uuid = id.parse()?;
    let service = match (parts.method.as_str(), tail.as_str()) {
        ("GET", "info/refs") => match parts.uri.query() {
            Some("service=git-upload-pack") => "git-upload-pack",
            Some("service=git-receive-pack") => "git-receive-pack",
            _ => return Ok(reply(StatusCode::BAD_REQUEST, "unknown service")),
        },
        ("POST", "git-upload-pack") => "git-upload-pack",
        ("POST", "git-receive-pack") => "git-receive-pack",
        _ => return Ok(reply(StatusCode::NOT_FOUND, "unknown route")),
    };
    let write = service == "git-receive-pack";
    let db = config.db().await?;
    if !permitted(&db, repo, principal, write).await? {
        return Ok(reply(StatusCode::FORBIDDEN, "repository access denied"));
    }
    if token.is_some() && write {
        return Ok(reply(StatusCode::FORBIDDEN, "snapshot is read-only"));
    }
    let snapshot = if let Some(token) = token {
        let row=db.query_opt("SELECT generation,storage_generation,refs,packs FROM pando_lab.snapshots WHERE id=$1 AND repo=$2 AND principal=$3 AND expires_at>clock_timestamp()",&[&token,&repo,&principal]).await?;
        let Some(row) = row else {
            return Ok(reply(StatusCode::NOT_FOUND, "snapshot unavailable"));
        };
        Snapshot {
            repo,
            generation: row.get(0),
            storage_generation: row.get(1),
            refs: serde_json::from_value(row.get(2))?,
            packs: serde_json::from_value(row.get(3))?,
        }
    } else {
        let snapshot = store::snapshot(config, repo).await?;
        if !write {
            if parts.method != "GET" {
                return Ok(reply(StatusCode::CONFLICT, "read snapshot required"));
            }
            let token = Uuid::new_v4();
            db.execute("INSERT INTO pando_lab.snapshots(id,repo,principal,generation,storage_generation,refs,packs) VALUES($1,$2,$3,$4,$5,$6,$7)",&[&token,&repo,&principal,&snapshot.generation,&snapshot.storage_generation,&serde_json::to_value(&snapshot.refs)?,&serde_json::to_value(&snapshot.packs)?]).await?;
            return Ok(Response::builder()
                .status(StatusCode::FOUND)
                .header(
                    header::LOCATION,
                    format!("/snapshots/{token}/{repo}.git/info/refs?service=git-upload-pack"),
                )
                .header(header::CACHE_CONTROL, "no-store")
                .body(Body::empty())?);
        }
        snapshot
    };
    if parts.headers.contains_key(header::CONTENT_ENCODING) {
        return Ok(reply(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "compressed requests not supported by lab",
        ));
    }
    if parts.method == "POST"
        && parts
            .headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            != Some(&format!("application/x-{service}-request"))
    {
        return Ok(reply(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Git request content type required",
        ));
    }
    let data = match to_bytes(body, LIMIT).await {
        Ok(b) => b,
        Err(_) => {
            return Ok(reply(
                StatusCode::PAYLOAD_TOO_LARGE,
                "lab fixture size limit",
            ));
        }
    };
    let ctl = control(config)?;
    let session = Session::new(config)?;
    store::materialize(config, &snapshot, &session.0, &ctl).await?;
    let op = if write && parts.method == "POST" {
        let id = Uuid::new_v4();
        db.execute("INSERT INTO pando_lab.operations(id,repo,principal,state) VALUES($1,$2,$3,'RECEIVING')",&[&id,&repo,&principal]).await?;
        Some(id)
    } else {
        None
    };
    let mut c = config.git_command(&session.0);
    // No caller-supplied Git environment is admitted through HTTP. The lab's
    // process environment is trusted and must not point at user repositories.
    c.args(["http-backend"])
        .env("GIT_PROJECT_ROOT", &session.0)
        .env("PATH_INFO", format!("/repo.git/{tail}"))
        .env("QUERY_STRING", parts.uri.query().unwrap_or(""))
        .env("REQUEST_METHOD", parts.method.as_str())
        .env(
            "CONTENT_TYPE",
            parts
                .headers
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or(""),
        )
        .env("CONTENT_LENGTH", data.len().to_string())
        .env("REMOTE_USER", principal)
        .env("REMOTE_ADDR", "127.0.0.1")
        .env("SERVER_PROTOCOL", "HTTP/1.1")
        .env("PANDO_REPO", repo.to_string())
        .env("PANDO_PRINCIPAL", principal)
        .env(
            "PANDO_STORAGE_GENERATION",
            snapshot.storage_generation.to_string(),
        );
    if let Some(op) = op {
        c.env("PANDO_OPERATION", op.to_string());
    }
    if let Some(protocol) = parts.headers.get("Git-Protocol") {
        c.env("HTTP_GIT_PROTOCOL", protocol.to_str()?);
    }
    let output = execute(c, data.to_vec()).await?;
    if !output.stderr.is_empty() {
        eprintln!("pando Git: {}", String::from_utf8_lossy(&output.stderr));
    }
    let split = output
        .stdout
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .context("invalid Git CGI response")?;
    let head = std::str::from_utf8(&output.stdout[..split])?;
    let mut response = Response::builder().status(StatusCode::OK);
    for line in head.split("\r\n") {
        let (key, value) = line.split_once(':').context("invalid CGI header")?;
        if key.eq_ignore_ascii_case("status") {
            response = response.status(
                value
                    .trim()
                    .split(' ')
                    .next()
                    .context("CGI status")?
                    .parse::<u16>()?,
            );
        } else if !key.eq_ignore_ascii_case("content-length") {
            response = response.header(key, value.trim());
        }
    }
    if let Some(op) = op {
        response = response.header("X-Pando-Operation", op.to_string());
    }
    Ok(response.body(Body::from(output.stdout[split + 4..].to_vec()))?)
}
