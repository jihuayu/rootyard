//! Real TLS-terminating forwarder over `axum::serve(..., build_signed_packfile_router)`
//! + ephemeral Root CA (`SAN=DNS:cdn.localhost,IP:127.0.0.1`) + stock Git helpers.

use std::{
    fs::File,
    io::{BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, ensure};
use rootyard::browse::packfile_uri::{
    PackHttpServerState, PackUriKeyring, SigningKeyMaterial, build_signed_packfile_router,
};

pub fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

pub fn shared_keyring() -> Arc<PackUriKeyring> {
    static RING: OnceLock<Arc<PackUriKeyring>> = OnceLock::new();
    Arc::clone(RING.get_or_init(|| {
        let mut r = PackUriKeyring::new();
        r.insert_active(SigningKeyMaterial::new("kid-v1", vec![0x55; 32]).unwrap());
        Arc::new(r)
    }))
}

pub fn resolve_git_binary() -> Result<PathBuf> {
    if let Ok(raw) = std::env::var("ROOTYARD_TEST_GIT") {
        return Ok(std::fs::canonicalize(raw)?);
    }
    for candidate in ["/usr/bin/git", "/usr/local/bin/git"] {
        let p = Path::new(candidate);
        if p.is_file() {
            return Ok(std::fs::canonicalize(p)?);
        }
    }
    let out = Command::new("git").arg("--exec-path").output().context("locate git")?;
    ensure!(out.status.success(), "git --exec-path failed");
    let which_out = Command::new("which").arg("git").output().context("which git")?;
    ensure!(which_out.status.success(), "which git failed");
    Ok(std::fs::canonicalize(String::from_utf8(which_out.stdout)?.trim())?)
}

pub fn git_cmd(args: &[&str], cwd: Option<&Path>, stdin_data: Option<&[u8]>) -> Result<Vec<u8>> {
    let mut cmd = Command::new("git");
    cmd.arg("-c")
        .arg("core.hooksPath=/dev/null")
        .arg("-c")
        .arg("commit.gpgsign=false")
        .arg("-c")
        .arg("tag.gpgsign=false")
        .args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    cmd.stdin(if stdin_data.is_some() { Stdio::piped() } else { Stdio::null() });
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

pub struct EphemeralCert {
    pub cert_path: PathBuf,
    pub server_cfg: Arc<rustls::ServerConfig>,
}

fn run_openssl(args: &[&str]) -> Result<()> {
    let status = Command::new("openssl")
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("spawn openssl")?;
    ensure!(status.success(), "openssl failed: {args:?}");
    Ok(())
}

pub fn build_ephemeral_tls_cert(dir: &Path) -> Result<EphemeralCert> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (ca_k, ca_c) = (dir.join("ca.key.pem"), dir.join("ca.cert.pem"));
    let (ext_p, l_key, l_csr, l_crt) =
        (dir.join("leaf.ext"), dir.join("cdn.key.pem"), dir.join("cdn.csr.pem"), dir.join("cdn.cert.pem"));
    run_openssl(&[
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "1",
        "-keyout",
        ca_k.to_str().unwrap(),
        "-out",
        ca_c.to_str().unwrap(),
        "-subj",
        "/CN=rootyard-test-ca",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
    ])?;
    std::fs::write(
        &ext_p,
        "[v3_req]\nbasicConstraints = CA:FALSE\nkeyUsage = digitalSignature, keyEncipherment\n\
         extendedKeyUsage = serverAuth\nsubjectAltName = DNS:cdn.localhost,IP:127.0.0.1\n",
    )?;
    run_openssl(&[
        "req",
        "-new",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        l_key.to_str().unwrap(),
        "-out",
        l_csr.to_str().unwrap(),
        "-subj",
        "/CN=cdn.localhost",
    ])?;
    run_openssl(&[
        "x509",
        "-req",
        "-in",
        l_csr.to_str().unwrap(),
        "-CA",
        ca_c.to_str().unwrap(),
        "-CAkey",
        ca_k.to_str().unwrap(),
        "-CAcreateserial",
        "-out",
        l_crt.to_str().unwrap(),
        "-days",
        "1",
        "-extfile",
        ext_p.to_str().unwrap(),
        "-extensions",
        "v3_req",
    ])?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let certs =
        rustls_pemfile::certs(&mut BufReader::new(File::open(&l_crt)?)).collect::<std::result::Result<Vec<_>, _>>()?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(File::open(&l_key)?))?.context("missing key")?;
    let server_cfg = Arc::new(
        rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(certs, key)?,
    );
    Ok(EphemeralCert { cert_path: ca_c, server_cfg })
}

pub struct TlsAxumCdnServer {
    pub port: u16,
    pub stop: Arc<AtomicBool>,
    pub tls_requests: Arc<AtomicUsize>,
    pub fail_first_n: Arc<AtomicUsize>,
    pub emit_oversized_chunks: Arc<AtomicBool>,
    axum_task: tokio::task::JoinHandle<()>,
}

impl Drop for TlsAxumCdnServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.axum_task.abort();
    }
}

struct TlsForwardCtx {
    cfg: Arc<rustls::ServerConfig>,
    axum_port: u16,
    tls_requests: Arc<AtomicUsize>,
    fail_first_n: Arc<AtomicUsize>,
    emit_oversized_chunks: Arc<AtomicBool>,
}

pub fn reserve_loopback_listener() -> Result<(TcpListener, u16)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let port = listener.local_addr()?.port();
    Ok((listener, port))
}

pub async fn spawn_tls_axum_cdn_server(
    tls_listener: TcpListener,
    tls_cfg: Arc<rustls::ServerConfig>,
    pack_state: Arc<PackHttpServerState>,
) -> Result<TlsAxumCdnServer> {
    let port = tls_listener.local_addr()?.port();
    let axum_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let axum_port = axum_listener.local_addr()?.port();
    let app = build_signed_packfile_router(pack_state);
    let axum_task = tokio::spawn(async move {
        let _ = axum::serve(axum_listener, app).await;
    });

    let stop = Arc::new(AtomicBool::new(false));
    let tls_requests = Arc::new(AtomicUsize::new(0));
    let fail_first_n = Arc::new(AtomicUsize::new(0));
    let emit_oversized_chunks = Arc::new(AtomicBool::new(false));
    let ctx = Arc::new(TlsForwardCtx {
        cfg: tls_cfg,
        axum_port,
        tls_requests: Arc::clone(&tls_requests),
        fail_first_n: Arc::clone(&fail_first_n),
        emit_oversized_chunks: Arc::clone(&emit_oversized_chunks),
    });
    let stop_c = Arc::clone(&stop);
    std::thread::spawn(move || {
        while !stop_c.load(Ordering::SeqCst) {
            match tls_listener.accept() {
                Ok((stream, _)) => {
                    let ctx_c = Arc::clone(&ctx);
                    std::thread::spawn(move || {
                        let _ = handle_tls_forward_conn(stream, &ctx_c);
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(10)),
                Err(_) => break,
            }
        }
    });
    Ok(TlsAxumCdnServer { port, stop, tls_requests, fail_first_n, emit_oversized_chunks, axum_task })
}

fn handle_tls_forward_conn(mut stream: TcpStream, ctx: &TlsForwardCtx) -> Result<()> {
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(15)))?;
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
    let (mut req_buf, mut chunk) = (Vec::new(), [0u8; 4096]);
    while !req_buf.windows(4).any(|w| w == b"\r\n\r\n") && req_buf.len() < 32768 {
        let r = tls.read(&mut chunk)?;
        if r == 0 {
            return Ok(());
        }
        req_buf.extend_from_slice(&chunk[..r]);
    }
    let idx = ctx.tls_requests.fetch_add(1, Ordering::SeqCst);
    if idx < ctx.fail_first_n.load(Ordering::SeqCst) {
        tls.write_all(
            b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 19\r\nConnection: close\r\n\r\ntransient cdn error",
        )?;
    } else if ctx.emit_oversized_chunks.load(Ordering::SeqCst) {
        tls.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n")?;
        let big = vec![b'X'; 4096];
        for _ in 0..8 {
            tls.write_all(format!("{:x}\r\n", big.len()).as_bytes())?;
            tls.write_all(&big)?;
            tls.write_all(b"\r\n")?;
        }
        tls.write_all(b"0\r\n\r\n")?;
    } else {
        let mut upstream = TcpStream::connect(("127.0.0.1", ctx.axum_port))?;
        upstream.set_read_timeout(Some(Duration::from_secs(15)))?;
        upstream.write_all(&req_buf)?;
        upstream.flush()?;
        let mut resp_chunk = [0u8; 16384];
        loop {
            let rn = upstream.read(&mut resp_chunk)?;
            if rn == 0 {
                break;
            }
            tls.write_all(&resp_chunk[..rn])?;
        }
    }
    tls.flush()?;
    tls.conn.send_close_notify();
    let _ = tls.flush();
    Ok(())
}
