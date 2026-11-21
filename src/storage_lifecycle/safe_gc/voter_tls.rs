//! Authenticated mTLS HTTPS transport plus bounded DER SAN extraction for `rootyard-safe-gc-voter` (#122).
use std::{
    fs::File,
    io::{BufReader, Read, Write},
    net::{SocketAddr, TcpStream, ToSocketAddrs},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned, pki_types::ServerName,
    server::WebPkiClientVerifier,
};
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::super::{SafeGcError, dist_auth::read_private_file};
use super::{VoterState, build_mtls_client_config, voter_cutpoint, voter_health_bytes, voter_shutdown_signal};

const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;
const MAX_BEARER_TOKEN_BYTES: usize = 4_096;
const MIN_BEARER_TOKEN_BYTES: usize = 32;
const MAX_CONNECTIONS: usize = 32;
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(15);
const HEADER_END: &[u8] = b"\r\n\r\n";
const MAX_PEER_CERT_DER_BYTES: usize = 64 * 1024;
const SAN_OID: &[u8] = &[0x55, 0x1d, 0x11];

fn io_error(err: impl std::fmt::Display) -> SafeGcError {
    SafeGcError::Io(err.to_string())
}

/// Pinned mTLS + `0600` Bearer-token client credentials used by a worker to poll `rootyard-safe-gc-voter`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SafeGcVoterClientAuth {
    pub ca_cert_pem: PathBuf,
    pub client_cert_pem: PathBuf,
    pub client_key_pem: PathBuf,
    pub server_name: String,
    pub auth_token_path: PathBuf,
}

impl SafeGcVoterClientAuth {
    /// Reject an empty server name or an empty credential path before any connection is attempted.
    pub fn validate(&self) -> Result<(), SafeGcError> {
        let paths = [&self.ca_cert_pem, &self.client_cert_pem, &self.client_key_pem, &self.auth_token_path];
        if self.server_name.trim().is_empty() || paths.iter().any(|path| path.as_os_str().is_empty()) {
            return Err(SafeGcError::ArmingRejected(
                "safe-gc voter client auth requires a non-empty server name and non-empty credential paths",
            ));
        }
        Ok(())
    }
}

/// Read a `0600` Bearer token, strip trailing newlines, and require >= 32 visible ASCII bytes.
pub fn load_private_bearer_token(path: &Path) -> Result<Zeroizing<Vec<u8>>, SafeGcError> {
    let bytes = read_private_file(path, MAX_BEARER_TOKEN_BYTES)?;
    let end = bytes.iter().rposition(|byte| *byte != b'\r' && *byte != b'\n').map_or(0, |pos| pos + 1);
    let token = &bytes[..end];
    if token.len() < MIN_BEARER_TOKEN_BYTES || !token.iter().all(|byte| (0x21..=0x7e).contains(byte)) {
        return Err(SafeGcError::ArmingRejected(
            "safe-gc voter bearer token must be at least 32 visible printable ASCII bytes after trimming",
        ));
    }
    Ok(Zeroizing::new(token.to_vec()))
}

/// Constant-time comparison of the `Authorization: Bearer` header against the pinned token.
pub fn constant_time_bearer_eq(expected: &[u8], auth_header: Option<&str>) -> bool {
    let Some(raw) = auth_header.and_then(|header| header.strip_prefix("Bearer ")) else { return false };
    let raw = raw.as_bytes();
    let mut diff = expected.len() ^ raw.len();
    for index in 0..expected.len().max(raw.len()) {
        let left = expected.get(index).copied().unwrap_or(0);
        let right = raw.get(index).copied().unwrap_or(0);
        diff |= usize::from(left ^ right);
    }
    diff == 0 && !expected.is_empty()
}

fn read_der_tlv(input: &[u8]) -> Result<(u8, &[u8], &[u8]), SafeGcError> {
    let malformed = || SafeGcError::Serialization("X.509 DER length is malformed".into());
    let (&tag, rest) = input.split_first().ok_or_else(malformed)?;
    let (&first, rest) = rest.split_first().ok_or_else(malformed)?;
    if first == 0x80 {
        return Err(malformed());
    }
    let (len, rest) = if first & 0x80 == 0 {
        (usize::from(first), rest)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 {
            return Err(malformed());
        }
        let (bytes, tail) = rest.split_at_checked(count).ok_or_else(malformed)?;
        if bytes[0] == 0 {
            return Err(malformed());
        }
        let len = bytes.iter().fold(0_usize, |acc, byte| (acc << 8) | usize::from(*byte));
        if len < 128 {
            return Err(malformed());
        }
        (len, tail)
    };
    let (value, trailing) = rest.split_at_checked(len).ok_or_else(malformed)?;
    Ok((tag, value, trailing))
}

pub fn extract_x509_dns_sans(cert_der: &[u8]) -> Result<Vec<String>, SafeGcError> {
    if cert_der.is_empty() || cert_der.len() > MAX_PEER_CERT_DER_BYTES {
        return Err(SafeGcError::Serialization("peer certificate DER size is invalid".into()));
    }
    let (tag, cert, trailing) = read_der_tlv(cert_der)?;
    if tag != 0x30 || !trailing.is_empty() {
        return Err(SafeGcError::Serialization("peer certificate is not a single X.509 SEQUENCE".into()));
    }
    let (tag, tbs, _) = read_der_tlv(cert)?;
    if tag != 0x30 {
        return Err(SafeGcError::Serialization("X.509 tbsCertificate is not a SEQUENCE".into()));
    }
    let mut rest = tbs;
    let (version_tag, _, version_rest) = read_der_tlv(rest)?;
    if version_tag == 0xa0 {
        rest = version_rest;
    }
    for expected in [0x02_u8, 0x30, 0x30, 0x30, 0x30, 0x30] {
        let (field_tag, _, field_rest) = read_der_tlv(rest)?;
        if field_tag != expected {
            return Err(SafeGcError::Serialization("X.509 tbsCertificate field order is invalid".into()));
        }
        rest = field_rest;
    }
    let mut dns_sans = Vec::new();
    let mut saw_san_ext = false;
    while !rest.is_empty() {
        let (tag, value, next) = read_der_tlv(rest)?;
        rest = next;
        if tag != 0xa3 {
            continue;
        }
        let (ext_tag, extensions, ext_trailing) = read_der_tlv(value)?;
        if ext_tag != 0x30 || !ext_trailing.is_empty() {
            return Err(SafeGcError::Serialization("X.509 extensions are not a SEQUENCE".into()));
        }
        let mut ext_rest = extensions;
        while !ext_rest.is_empty() {
            let (ext_seq_tag, extension, next) = read_der_tlv(ext_rest)?;
            ext_rest = next;
            if ext_seq_tag != 0x30 {
                return Err(SafeGcError::Serialization("X.509 extension is not a SEQUENCE".into()));
            }
            let (oid_tag, oid, oid_rest) = read_der_tlv(extension)?;
            if oid_tag != 0x06 {
                return Err(SafeGcError::Serialization("X.509 extension OID is invalid".into()));
            }
            let (mut value_tag, mut ext_value, mut value_rest) = read_der_tlv(oid_rest)?;
            if value_tag == 0x01 {
                let (next_tag, next_value, next_rest) = read_der_tlv(value_rest)?;
                value_tag = next_tag;
                ext_value = next_value;
                value_rest = next_rest;
            }
            if value_tag != 0x04 || !value_rest.is_empty() {
                return Err(SafeGcError::Serialization("X.509 extension value is invalid".into()));
            }
            if oid != SAN_OID {
                continue;
            }
            if saw_san_ext {
                return Err(SafeGcError::Serialization("duplicate subjectAltName extension".into()));
            }
            saw_san_ext = true;
            let (gn_tag, general_names, gn_trailing) = read_der_tlv(ext_value)?;
            if gn_tag != 0x30 || !gn_trailing.is_empty() {
                return Err(SafeGcError::Serialization("X.509 subjectAltName is not a SEQUENCE".into()));
            }
            let mut gn_rest = general_names;
            while !gn_rest.is_empty() {
                let (gn_tag, gn_value, gn_next) = read_der_tlv(gn_rest)?;
                gn_rest = gn_next;
                if gn_tag != 0x82 {
                    continue;
                }
                if gn_value.is_empty() || !gn_value.iter().all(|byte| byte.is_ascii() && !byte.is_ascii_control()) {
                    return Err(SafeGcError::Serialization("X.509 dNSName SAN is invalid".into()));
                }
                dns_sans.push(
                    std::str::from_utf8(gn_value)
                        .map_err(|_| SafeGcError::Serialization("X.509 dNSName SAN is not UTF-8".into()))?
                        .to_owned(),
                );
            }
        }
    }
    Ok(dns_sans)
}

pub fn peer_cert_matches_allowed_san(cert_der: &[u8], allowed_client_san: &str) -> bool {
    !allowed_client_san.is_empty()
        && extract_x509_dns_sans(cert_der).is_ok_and(|sans| sans.iter().any(|san| san.as_str() == allowed_client_san))
}

pub fn build_mtls_server_config(
    ca_cert_pem: &Path,
    server_cert_pem: &Path,
    server_key_pem: &Path,
) -> Result<Arc<ServerConfig>, SafeGcError> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut roots = RootCertStore::empty();
    let ca = File::open(ca_cert_pem).map_err(io_error)?;
    for cert in rustls_pemfile::certs(&mut BufReader::new(ca)) {
        roots.add(cert.map_err(io_error)?).map_err(io_error)?;
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots)).build().map_err(io_error)?;
    let server = File::open(server_cert_pem).map_err(io_error)?;
    let certs = rustls_pemfile::certs(&mut BufReader::new(server))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(io_error)?;
    let key_file = File::open(server_key_pem).map_err(io_error)?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(key_file))
        .map_err(io_error)?
        .ok_or(SafeGcError::ArmingRejected("mTLS server private key missing"))?;
    let config = ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(io_error)?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .map_err(io_error)?;
    Ok(Arc::new(config))
}

type ServerTlsStream = StreamOwned<ServerConnection, TcpStream>;

fn read_http_header<S: Read>(stream: &mut S) -> Result<(Vec<u8>, Vec<u8>), SafeGcError> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 4_096];
    loop {
        let read = stream.read(&mut chunk).map_err(io_error)?;
        if read == 0 {
            return Err(SafeGcError::Io("HTTP peer closed before the header completed".into()));
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(start) = buffer.windows(HEADER_END.len()).position(|window| window == HEADER_END) {
            let rest = buffer.split_off(start + HEADER_END.len());
            return Ok((buffer, rest));
        }
        if buffer.len() > MAX_HEADER_BYTES {
            return Err(SafeGcError::Serialization("HTTP header exceeds 16 KiB".into()));
        }
    }
}

fn parse_http_request(header: &[u8]) -> Result<(String, String, Option<String>), SafeGcError> {
    let text =
        std::str::from_utf8(header).map_err(|_| SafeGcError::Serialization("HTTP header is not UTF-8".into()))?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next().ok_or_else(|| SafeGcError::Serialization("HTTP request line is missing".into()))?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or_else(|| SafeGcError::Serialization("HTTP method is missing".into()))?.to_owned();
    let path = parts.next().ok_or_else(|| SafeGcError::Serialization("HTTP path is missing".into()))?.to_owned();
    let mut auth_header = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else { continue };
        if name.eq_ignore_ascii_case("authorization") {
            auth_header = Some(value.trim().to_owned());
            break;
        }
    }
    Ok((method, path, auth_header))
}

fn read_tls_request(
    stream: tokio::net::TcpStream,
    server_config: Arc<ServerConfig>,
) -> Result<(ServerTlsStream, String, String, Option<String>, Option<Vec<u8>>), SafeGcError> {
    let std_stream = stream.into_std().map_err(io_error)?;
    std_stream.set_nonblocking(false).map_err(io_error)?;
    std_stream.set_read_timeout(Some(CONNECTION_TIMEOUT)).map_err(io_error)?;
    std_stream.set_write_timeout(Some(CONNECTION_TIMEOUT)).map_err(io_error)?;
    let connection = ServerConnection::new(server_config).map_err(io_error)?;
    let mut tls = StreamOwned::new(connection, std_stream);
    let (header, _body) = read_http_header(&mut tls)?;
    let leaf_der = tls.conn.peer_certificates().and_then(|certs| certs.first()).map(|cert| cert.as_ref().to_vec());
    let (method, path, auth_header) = parse_http_request(&header)?;
    Ok((tls, method, path, auth_header, leaf_der))
}

fn write_tls_response(
    mut tls: ServerTlsStream,
    code: u16,
    reason: &'static str,
    body: &[u8],
) -> Result<(), SafeGcError> {
    let head = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    tls.write_all(head.as_bytes()).map_err(io_error)?;
    tls.write_all(body).map_err(io_error)?;
    tls.flush().map_err(io_error)?;
    tls.conn.send_close_notify();
    let _ = tls.flush();
    Ok(())
}

async fn dispatch_https_request(
    state: &VoterState,
    expected_token: &[u8],
    leaf_cert_der: Option<&[u8]>,
    method: &str,
    path: &str,
    auth_header: Option<&str>,
) -> (u16, &'static str, Vec<u8>) {
    if !leaf_cert_der.is_some_and(|der| peer_cert_matches_allowed_san(der, &state.config.allowed_client_san)) {
        return (403, "Forbidden", br#"{"error":"client certificate SAN not authorized"}"#.to_vec());
    }
    if !constant_time_bearer_eq(expected_token, auth_header) {
        return (401, "Unauthorized", br#"{"error":"unauthorized"}"#.to_vec());
    }
    if method != "GET" {
        return (405, "Method Not Allowed", br#"{"error":"method not allowed"}"#.to_vec());
    }
    if path == "/healthz" {
        return (200, "OK", voter_health_bytes(state));
    }
    let Some(raw_repo) = path.strip_prefix("/v1/safe-gc/cutpoint/") else {
        return (404, "Not Found", br#"{"error":"not found"}"#.to_vec());
    };
    let Ok(repo_id) = Uuid::parse_str(raw_repo) else {
        return (400, "Bad Request", br#"{"error":"invalid repository id"}"#.to_vec());
    };
    voter_cutpoint(state, repo_id).await
}

async fn handle_https_connection(
    stream: tokio::net::TcpStream,
    state: Arc<VoterState>,
    expected_token: Zeroizing<Vec<u8>>,
    server_config: Arc<ServerConfig>,
) -> Result<(), SafeGcError> {
    let request = tokio::task::spawn_blocking(move || read_tls_request(stream, server_config));
    let (tls, method, path, auth_header, leaf_der) = request.await.map_err(io_error)??;
    let header = auth_header.as_deref();
    let (code, reason, body) =
        dispatch_https_request(&state, &expected_token, leaf_der.as_deref(), &method, &path, header).await;
    tokio::task::spawn_blocking(move || write_tls_response(tls, code, reason, &body)).await.map_err(io_error)??;
    Ok(())
}

/// Serve bounded mTLS HTTPS/1.1 requests until shutdown, rejecting every unauthenticated peer.
pub(super) async fn serve_mtls_https_voter(
    listener: tokio::net::TcpListener,
    state: Arc<VoterState>,
    expected_token: Zeroizing<Vec<u8>>,
    server_config: Arc<ServerConfig>,
) -> Result<(), SafeGcError> {
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let shutdown = voter_shutdown_signal();
    tokio::pin!(shutdown);
    loop {
        let accepted = tokio::select! {
            biased;
            _ = &mut shutdown => break,
            accepted = listener.accept() => accepted,
        };
        let (stream, _peer) = accepted.map_err(io_error)?;
        let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else { continue };
        let state = Arc::clone(&state);
        let token = expected_token.clone();
        let config = Arc::clone(&server_config);
        tokio::spawn(async move {
            let _permit = permit;
            let _ = handle_https_connection(stream, state, token, config).await;
        });
    }
    Ok(())
}

fn parse_http_response(header: &[u8]) -> Result<(u16, usize), SafeGcError> {
    let text =
        std::str::from_utf8(header).map_err(|_| SafeGcError::Serialization("HTTP header is not UTF-8".into()))?;
    let mut lines = text.split("\r\n");
    let status_line = lines.next().ok_or_else(|| SafeGcError::Serialization("HTTP status line is missing".into()))?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| SafeGcError::Serialization("HTTP status code is invalid".into()))?;
    let mut content_length = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else { continue };
        if name.eq_ignore_ascii_case("content-length") {
            let parsed = value
                .trim()
                .parse::<usize>()
                .map_err(|_| SafeGcError::Serialization("HTTP content-length is invalid".into()))?;
            content_length = Some(parsed);
        }
    }
    let content_length = content_length.ok_or_else(|| SafeGcError::Serialization("content-length missing".into()))?;
    if content_length > MAX_BODY_BYTES {
        return Err(SafeGcError::Serialization("HTTP body exceeds 16 MiB".into()));
    }
    Ok((status, content_length))
}

fn request_over_tls(
    sock_addr: SocketAddr,
    server_name: String,
    client_tls: Arc<ClientConfig>,
    request: String,
    timeout: Duration,
) -> Result<(u16, Vec<u8>), SafeGcError> {
    let tcp = TcpStream::connect_timeout(&sock_addr, timeout).map_err(io_error)?;
    tcp.set_read_timeout(Some(timeout)).map_err(io_error)?;
    tcp.set_write_timeout(Some(timeout)).map_err(io_error)?;
    let name = ServerName::try_from(server_name).map_err(|_| SafeGcError::ArmingRejected("invalid server name"))?;
    let connection = ClientConnection::new(client_tls, name).map_err(io_error)?;
    let mut tls = StreamOwned::new(connection, tcp);
    tls.write_all(request.as_bytes()).map_err(io_error)?;
    tls.flush().map_err(io_error)?;
    let (header, mut body) = read_http_header(&mut tls)?;
    let (status, content_length) = parse_http_response(&header)?;
    if body.len() < content_length {
        let mut rest = vec![0_u8; content_length - body.len()];
        tls.read_exact(&mut rest).map_err(io_error)?;
        body.extend_from_slice(&rest);
    }
    body.truncate(content_length);
    tls.conn.send_close_notify();
    let _ = tls.flush();
    Ok((status, body))
}

/// Issue one authenticated mTLS HTTPS `GET` and return the status plus bounded body bytes.
pub async fn request_voter_https(
    endpoint_url: &str,
    path: &str,
    auth: &SafeGcVoterClientAuth,
    bearer_override: Option<&str>,
    timeout: Duration,
) -> Result<(u16, Vec<u8>), SafeGcError> {
    let Some(rest) = endpoint_url.strip_prefix("https://") else {
        return Err(SafeGcError::ArmingRejected("voter endpoint_url must use https://"));
    };
    let host_port = rest.split('/').next().unwrap_or(rest);
    if host_port.is_empty() {
        return Err(SafeGcError::ArmingRejected("voter endpoint_url must include a host"));
    }
    let sock_addr = host_port
        .to_socket_addrs()
        .map_err(io_error)?
        .next()
        .ok_or(SafeGcError::ArmingRejected("voter endpoint_url does not resolve"))?;
    let client_tls = build_mtls_client_config(&auth.ca_cert_pem, &auth.client_cert_pem, &auth.client_key_pem)?;
    let token = match bearer_override {
        Some(raw) => Zeroizing::new(raw.trim_end_matches(['\r', '\n']).as_bytes().to_vec()),
        None => load_private_bearer_token(&auth.auth_token_path)?,
    };
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host_port}\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
        String::from_utf8_lossy(&token)
    );
    let server_name = auth.server_name.clone();
    tokio::task::spawn_blocking(move || request_over_tls(sock_addr, server_name, client_tls, request, timeout))
        .await
        .map_err(io_error)?
}

#[cfg(test)]
#[path = "tests_voter_tls.rs"]
mod tests;
