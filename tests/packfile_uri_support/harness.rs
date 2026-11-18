//! Shared TLS + Axum Smart HTTP v2 + stock Git test harness for Issue #185.

use std::{
    fs::File,
    io::{BufReader, Read, Write},
    net::{IpAddr, Ipv4Addr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, ensure};
use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::Response,
    routing::{get, post},
};
use rootyard::{
    browse::packfile_uri::{
        CdnHealthState, DeliveryMode, DeliveryPlanRequest, DeliveryPlanner, LivePackReadAuthorizer,
        OffloadPolicyConfig, PackClosurePlan, PackHttpServerState, PackObjectFormat, PackUriKeyring,
        PackfileClosureMember, PackfileUriError, SigningKeyMaterial, encode_fetch_v2_response,
        format_fetch_capability_line, parse_fetch_v2_request, protocol_v2::push_pkt_line, serve_signed_packfile,
    },
    cache_wake::replica_cache::lease_pin::AuthTask,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub struct StaticAuth(pub Arc<AtomicBool>);

impl LivePackReadAuthorizer for StaticAuth {
    fn authorize_pack_download<'a>(
        &'a self,
        _tenant_id: Uuid,
        _repository_id: Uuid,
        _actor_id: Uuid,
        _pack_oid: &'a str,
        _pin_id: Uuid,
    ) -> AuthTask<'a, Result<(), PackfileUriError>> {
        let allow = self.0.load(Ordering::SeqCst);
        Box::pin(async move { if allow { Ok(()) } else { Err(PackfileUriError::Unauthorized) } })
    }
}

pub fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

pub fn public_ips() -> Vec<IpAddr> {
    vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]
}

pub fn shared_keyring() -> Arc<PackUriKeyring> {
    static RING: OnceLock<Arc<PackUriKeyring>> = OnceLock::new();
    Arc::clone(RING.get_or_init(|| {
        let mut r = PackUriKeyring::new();
        r.insert_active(SigningKeyMaterial::new("kid-v1", vec![0x55; 32]).unwrap());
        Arc::new(r)
    }))
}

pub fn git_cmd(args: &[&str], cwd: Option<&Path>, stdin_data: Option<&[u8]>) -> Result<Vec<u8>> {
    let mut cmd = Command::new("git");
    cmd.args(args).env("GIT_TERMINAL_PROMPT", "0").stdout(Stdio::piped()).stderr(Stdio::piped());
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    if stdin_data.is_some() {
        cmd.stdin(Stdio::piped());
    }
    let mut child = cmd.spawn().with_context(|| format!("spawn git {args:?}"))?;
    if let Some(data) = stdin_data
        && let Some(mut stdin) = child.stdin.take()
    {
        stdin.write_all(data)?;
    }
    let out = child.wait_with_output()?;
    ensure!(out.status.success(), "git {args:?} failed: {}", String::from_utf8_lossy(&out.stderr));
    Ok(out.stdout)
}

pub struct PreparedRepo {
    pub head_oid: String,
    pub base_pack: Vec<u8>,
    pub residual_pack: Vec<u8>,
    pub full_pack: Vec<u8>,
    pub pack_hash: String,
    pub sha256_hex: String,
}

pub fn prepare_dual_pack_repo(dir: &Path, fmt: PackObjectFormat) -> Result<PreparedRepo> {
    let bare = dir.join(format!("origin_{}.git", fmt.as_str()));
    let work = dir.join(format!("work_{}", fmt.as_str()));
    git_cmd(&["init", "--bare", fmt.git_init_flag(), bare.to_str().unwrap()], None, None)?;
    git_cmd(&["clone", bare.to_str().unwrap(), work.to_str().unwrap()], None, None)?;
    git_cmd(&["-C", work.to_str().unwrap(), "config", "user.email", "ci@rootyard.test"], None, None)?;
    git_cmd(&["-C", work.to_str().unwrap(), "config", "user.name", "CI"], None, None)?;
    std::fs::write(work.join("base.txt"), vec![b'B'; 8_192])?;
    git_cmd(&["-C", work.to_str().unwrap(), "add", "base.txt"], None, None)?;
    git_cmd(&["-C", work.to_str().unwrap(), "-c", "commit.gpgsign=false", "commit", "-m", "base"], None, None)?;
    git_cmd(&["-C", work.to_str().unwrap(), "push", "origin", "HEAD:refs/heads/main"], None, None)?;
    git_cmd(&["-C", bare.to_str().unwrap(), "repack", "-ad"], None, None)?;
    let c1 = String::from_utf8(git_cmd(&["-C", bare.to_str().unwrap(), "rev-parse", "refs/heads/main"], None, None)?)?
        .trim()
        .to_owned();
    let pack_path = std::fs::read_dir(bare.join("objects/pack"))?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|e| e == "pack"))
        .context("missing base pack")?;
    let base_pack = std::fs::read(&pack_path)?;
    let trailer_len = fmt.oid_hex_len() / 2;
    let pack_hash = hex::encode(&base_pack[base_pack.len() - trailer_len..]);
    let sha256_hex = hex::encode(Sha256::digest(&base_pack));

    std::fs::write(work.join("delta.txt"), "residual delta commit\n")?;
    git_cmd(&["-C", work.to_str().unwrap(), "add", "delta.txt"], None, None)?;
    git_cmd(&["-C", work.to_str().unwrap(), "-c", "commit.gpgsign=false", "commit", "-m", "delta"], None, None)?;
    git_cmd(&["-C", work.to_str().unwrap(), "push", "origin", "HEAD:refs/heads/main"], None, None)?;
    let c2 = String::from_utf8(git_cmd(&["-C", bare.to_str().unwrap(), "rev-parse", "refs/heads/main"], None, None)?)?
        .trim()
        .to_owned();
    let residual_pack = git_cmd(
        &["-C", bare.to_str().unwrap(), "pack-objects", "--revs", "--stdout"],
        None,
        Some(format!("{c2}\n^{c1}\n").as_bytes()),
    )?;
    let full_pack = git_cmd(
        &["-C", bare.to_str().unwrap(), "pack-objects", "--revs", "--stdout"],
        None,
        Some(format!("{c2}\n").as_bytes()),
    )?;
    Ok(PreparedRepo { head_oid: c2, base_pack, residual_pack, full_pack, pack_hash, sha256_hex })
}

pub struct EphemeralCert {
    pub cert_path: PathBuf,
    pub server_cfg: Arc<rustls::ServerConfig>,
}

pub fn build_ephemeral_tls_cert(dir: &Path) -> Result<EphemeralCert> {
    let cert_path = dir.join("cdn.cert.pem");
    let key_path = dir.join("cdn.key.pem");
    let status = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            key_path.to_str().unwrap(),
            "-out",
            cert_path.to_str().unwrap(),
            "-days",
            "1",
            "-subj",
            "/CN=cdn.rootyard.test",
            "-addext",
            "subjectAltName=DNS:cdn.rootyard.test,IP:127.0.0.1",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("spawn openssl")?;
    ensure!(status.success(), "openssl cert generation failed");
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let certs = rustls_pemfile::certs(&mut BufReader::new(File::open(&cert_path)?))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(File::open(&key_path)?))?.context("missing key")?;
    let server_cfg = Arc::new(
        rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(certs, key)?,
    );
    Ok(EphemeralCert { cert_path, server_cfg })
}

pub struct TlsCdnServer {
    pub port: u16,
    pub stop: Arc<AtomicBool>,
    pub tls_requests: Arc<AtomicUsize>,
    pub fail_first_n: Arc<AtomicUsize>,
}

impl Drop for TlsCdnServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

struct TlsCdnConnCtx {
    cfg: Arc<rustls::ServerConfig>,
    state: Arc<PackHttpServerState>,
    tenant: Uuid,
    repo: Uuid,
    pack_oid: String,
    fmt: PackObjectFormat,
    tls_requests: Arc<AtomicUsize>,
    fail_first_n: Arc<AtomicUsize>,
    rt: tokio::runtime::Handle,
}

pub fn spawn_tls_cdn_server(
    tls_cfg: Arc<rustls::ServerConfig>,
    pack_state: Arc<PackHttpServerState>,
    tenant: Uuid,
    repo: Uuid,
    pack_oid: String,
    fmt: PackObjectFormat,
    rt_handle: tokio::runtime::Handle,
) -> Result<TlsCdnServer> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let port = listener.local_addr()?.port();
    let stop = Arc::new(AtomicBool::new(false));
    let tls_requests = Arc::new(AtomicUsize::new(0));
    let fail_first_n = Arc::new(AtomicUsize::new(0));
    let ctx = Arc::new(TlsCdnConnCtx {
        cfg: tls_cfg,
        state: pack_state,
        tenant,
        repo,
        pack_oid,
        fmt,
        tls_requests: Arc::clone(&tls_requests),
        fail_first_n: Arc::clone(&fail_first_n),
        rt: rt_handle,
    });
    let stop_c = Arc::clone(&stop);
    std::thread::spawn(move || {
        while !stop_c.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let ctx_c = Arc::clone(&ctx);
                    std::thread::spawn(move || {
                        let _ = handle_tls_cdn_conn(stream, &ctx_c);
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(10)),
                Err(_) => break,
            }
        }
    });
    Ok(TlsCdnServer { port, stop, tls_requests, fail_first_n })
}

fn handle_tls_cdn_conn(mut stream: TcpStream, ctx: &TlsCdnConnCtx) -> Result<()> {
    stream.set_nonblocking(false)?;
    let mut peek = [0u8; 8];
    let n = stream.peek(&mut peek)?;
    if peek[..n].starts_with(b"CONNECT ") {
        let (mut head, mut byte) = (Vec::new(), [0u8; 1]);
        while !head.ends_with(b"\r\n\r\n") && head.len() < 8192 {
            if stream.read(&mut byte)? == 0 {
                return Ok(());
            }
            head.push(byte[0]);
        }
        stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
        stream.flush()?;
    }
    let conn = rustls::ServerConnection::new(Arc::clone(&ctx.cfg))?;
    let mut tls = rustls::StreamOwned::new(conn, stream);
    let (mut req_buf, mut chunk) = (Vec::new(), [0u8; 2048]);
    while !req_buf.windows(4).any(|w| w == b"\r\n\r\n") && req_buf.len() < 16384 {
        let r = tls.read(&mut chunk)?;
        if r == 0 {
            return Ok(());
        }
        req_buf.extend_from_slice(&chunk[..r]);
    }
    let target = String::from_utf8_lossy(&req_buf)
        .lines()
        .next()
        .unwrap_or("")
        .split_whitespace()
        .nth(1)
        .unwrap_or("")
        .to_owned();
    let idx = ctx.tls_requests.fetch_add(1, Ordering::SeqCst);
    let (status, body) = if idx < ctx.fail_first_n.load(Ordering::SeqCst) {
        ("503 Service Unavailable", b"transient cdn error".to_vec())
    } else {
        let full_uri = format!("https://cdn.rootyard.test{target}");
        match ctx.rt.block_on(serve_signed_packfile(
            &ctx.state,
            &full_uri,
            ctx.tenant,
            ctx.repo,
            &ctx.pack_oid,
            ctx.fmt,
            Uuid::nil(),
        )) {
            Ok(bytes) => ("200 OK", bytes),
            Err(PackfileUriError::Unauthorized) => ("403 Forbidden", b"unauthorized".to_vec()),
            Err(_) => ("410 Gone", b"rejected".to_vec()),
        }
    };
    let hdr = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    tls.write_all(hdr.as_bytes())?;
    tls.write_all(&body)?;
    tls.flush()?;
    Ok(())
}

pub struct OriginState {
    pub planner: Arc<DeliveryPlanner>,
    pub auth: Arc<StaticAuth>,
    pub policy: OffloadPolicyConfig,
    pub tenant: Uuid,
    pub repo: Uuid,
    pub fmt: PackObjectFormat,
    pub head_oid: String,
    pub member: PackfileClosureMember,
    pub residual_pack: Vec<u8>,
    pub full_pack: Vec<u8>,
    pub inline_count: AtomicU64,
    pub offload_count: AtomicU64,
}

pub async fn spawn_git_origin(state: Arc<OriginState>) -> Result<u16> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let app = Router::new()
        .route("/repo.git/info/refs", get(handle_info_refs))
        .route("/repo.git/git-upload-pack", post(handle_upload_pack))
        .with_state(state);
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(port)
}

async fn handle_info_refs(State(st): State<Arc<OriginState>>, headers: HeaderMap) -> Response {
    let proto_v2 = headers.get("git-protocol").and_then(|v| v.to_str().ok()).is_some_and(|v| v.contains("version=2"));
    let mut out = Vec::new();
    let lines = if proto_v2 {
        vec![
            "# service=git-upload-pack\n".to_owned(),
            String::new(),
            "version 2\n".to_owned(),
            "agent=rootyard/test\n".to_owned(),
            "ls-refs=unborn\n".to_owned(),
            format!("fetch={}\n", format_fetch_capability_line(st.policy.enabled)),
            format!("object-format={}\n", st.fmt.as_str()),
        ]
    } else {
        vec![format!("{} refs/heads/main\0multi_ack_detailed\n", st.head_oid)]
    };
    for line in lines {
        if line.is_empty() {
            out.extend_from_slice(b"0000");
        } else {
            push_pkt_line(&mut out, line.as_bytes()).unwrap();
        }
    }
    out.extend_from_slice(b"0000");
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/x-git-upload-pack-advertisement")
        .header(header::CONNECTION, "close")
        .body(axum::body::Body::from(out))
        .unwrap()
}

async fn handle_upload_pack(State(st): State<Arc<OriginState>>, body: Bytes) -> Response {
    let text = String::from_utf8_lossy(&body);
    let resp_bytes = if text.contains("command=ls-refs") {
        let mut out = Vec::new();
        push_pkt_line(&mut out, format!("{} refs/heads/main\n", st.head_oid).as_bytes()).unwrap();
        out.extend_from_slice(b"0000");
        out
    } else {
        let fetch_req = parse_fetch_v2_request(&body, st.fmt).unwrap();
        let closure = PackClosurePlan {
            total_objects: 6,
            total_inline_bytes: st.full_pack.len() as u64,
            offload_candidates: vec![st.member.clone()],
            residual_inline_objects: 3,
            residual_inline_bytes: st.residual_pack.len() as u64,
        };
        let planned = st
            .planner
            .plan_fetch(
                st.auth.as_ref(),
                &DeliveryPlanRequest {
                    tenant_id: st.tenant,
                    repository_id: st.repo,
                    actor_id: Uuid::new_v4(),
                    gate_revision: 1,
                    object_format: st.fmt,
                    fetch_req: &fetch_req,
                    closure: &closure,
                    cdn_health: CdnHealthState::Healthy,
                    allowed_host: "cdn.rootyard.test",
                    now_unix: now_unix(),
                    resolved_ips: &public_ips(),
                    policy: &st.policy,
                    active_queue_saturated: false,
                },
            )
            .await
            .unwrap();
        match &planned.mode {
            DeliveryMode::OffloadPlusResidual { .. } => {
                st.offload_count.fetch_add(1, Ordering::SeqCst);
                encode_fetch_v2_response(&planned.mode, &st.residual_pack, true).unwrap()
            }
            DeliveryMode::InlineFallback { .. } => {
                st.inline_count.fetch_add(1, Ordering::SeqCst);
                encode_fetch_v2_response(&planned.mode, &st.full_pack, false).unwrap()
            }
        }
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/x-git-upload-pack-result")
        .header(header::CONNECTION, "close")
        .body(axum::body::Body::from(resp_bytes))
        .unwrap()
}
