//! Bounded HTTP/1.1 codec shared by the loopback proxy, its capture paths and
//! the service start-up diagnostics.
//!
//! Every read is bounded by a deadline and a size; chunked bodies are decoded
//! and every `Content-Length` body is read exactly. A response that ends early
//! is reported as truncated and is never trusted as a complete Git result.
use std::time::Duration;

use tokio::time::Instant;

use anyhow::{Result, anyhow, bail, ensure};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    time::{timeout, timeout_at},
};

pub(super) const MAX_HEAD_BYTES: usize = 64 * 1024;

/// Connection-level byte budgets handed to the codec.
pub struct Bounds<'a> {
    pub max_body: usize,
    pub max_response: usize,
    pub idle: &'a Duration,
}

pub(super) struct BackendTraffic {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub truncated: bool,
}

/// Case-insensitive lookup of the first header with `name` (stored lowercase).
pub(super) fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers.iter().find(|(key, _)| key == name).map(|(_, value)| value.as_str())
}

fn chunked(headers: &[(String, String)]) -> bool {
    header(headers, "transfer-encoding").is_some_and(|value| value.to_ascii_lowercase().contains("chunked"))
}

pub(super) fn connection_closed(headers: &[(String, String)]) -> bool {
    header(headers, "connection").is_some_and(|value| value.eq_ignore_ascii_case("close"))
}

/// One parsed request head: `(method, target, lowercase headers)`.
pub(super) type ParsedHead = (String, String, Vec<(String, String)>);

pub(super) fn parse_head(head: &[u8]) -> Result<ParsedHead> {
    let text = std::str::from_utf8(head).map_err(|_| anyhow!("proxy request head is not ASCII"))?;
    let mut lines = text.split("\r\n");
    let request = lines.next().ok_or_else(|| anyhow!("proxy request has no request line"))?;
    let mut parts = request.split(' ');
    let (Some(method), Some(target), Some(version), None) = (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        bail!("proxy request line is malformed");
    };
    ensure!(matches!(version, "HTTP/1.1" | "HTTP/1.0"), "unsupported request version");
    ensure!(target.starts_with('/'), "proxy request target must be an absolute path");
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(':').ok_or_else(|| anyhow!("proxy request header is malformed"))?;
        headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
    }
    Ok((method.to_owned(), target.to_owned(), headers))
}

pub(super) async fn read_head<R: AsyncBufReadExt + Unpin>(reader: &mut R, idle: Duration) -> Result<Option<Vec<u8>>> {
    let mut head = Vec::new();
    let mut line = Vec::new();
    loop {
        line.clear();
        let read = timeout(idle, reader.read_until(b'\n', &mut line))
            .await
            .map_err(|_| anyhow!("proxy client header read timed out"))??;
        if read == 0 {
            ensure!(head.is_empty(), "proxy client closed inside a request head");
            return Ok(None);
        }
        ensure!(head.len() + line.len() <= MAX_HEAD_BYTES, "proxy request head exceeds its bound");
        if line == b"\r\n" || line == b"\n" {
            return Ok(Some(std::mem::take(&mut head)));
        }
        head.extend_from_slice(&line);
    }
}

/// Read one client body under `max_body`: chunked decoding or an exact
/// `Content-Length`; every read is bounded by `idle`.
pub(super) async fn read_body<R: AsyncBufReadExt + Unpin>(
    reader: &mut R,
    headers: &[(String, String)],
    bounds: &Bounds<'_>,
) -> Result<Vec<u8>> {
    let budget = *bounds.idle;
    let mut body = Vec::new();
    if chunked(headers) {
        loop {
            let mut size_line = String::new();
            ensure!(
                timeout(budget, reader.read_line(&mut size_line))
                    .await
                    .map_err(|_| anyhow!("proxy chunk read timed out"))??
                    > 0,
                "proxy client closed inside a chunked body"
            );
            let size_text = size_line.trim().split(';').next().unwrap_or("");
            let size = usize::from_str_radix(size_text, 16).map_err(|_| anyhow!("proxy chunk size is invalid"))?;
            if size == 0 {
                loop {
                    let mut trailer = String::new();
                    ensure!(
                        timeout(budget, reader.read_line(&mut trailer))
                            .await
                            .map_err(|_| anyhow!("proxy trailer read timed out"))??
                            > 0,
                        "proxy client closed inside chunk trailers"
                    );
                    if trailer.trim().is_empty() {
                        return Ok(body);
                    }
                }
            }
            ensure!(body.len() + size <= bounds.max_body, "proxy request body exceeds its bound");
            let mut chunk = vec![0u8; size];
            timeout(budget, reader.read_exact(&mut chunk))
                .await
                .map_err(|_| anyhow!("proxy chunk read timed out"))??;
            body.extend_from_slice(&chunk);
            let mut terminator = [0u8; 2];
            timeout(budget, reader.read_exact(&mut terminator))
                .await
                .map_err(|_| anyhow!("proxy chunk terminator read timed out"))??;
            ensure!(&terminator == b"\r\n", "proxy chunk terminator is invalid");
        }
    }
    let length = match header(headers, "content-length") {
        Some(value) => value.parse::<usize>().map_err(|_| anyhow!("proxy request content length is invalid"))?,
        None => 0,
    };
    ensure!(length <= bounds.max_body, "proxy request body exceeds its bound");
    body.resize(length, 0);
    if length > 0 {
        timeout(budget, reader.read_exact(&mut body))
            .await
            .map_err(|_| anyhow!("proxy request body read timed out"))??;
    }
    Ok(body)
}

fn filter_request_headers(headers: &[(String, String)]) -> Vec<(String, String)> {
    headers
        .iter()
        .filter(|(name, _)| {
            !matches!(
                name.as_str(),
                "connection" | "proxy-connection" | "keep-alive" | "transfer-encoding" | "content-length" | "expect"
            )
        })
        .cloned()
        .collect()
}

pub(super) async fn write_request<W: AsyncWrite + Unpin>(
    writer: &mut W,
    method: &str,
    target: &str,
    headers: &[(String, String)],
    body: &[u8],
    bounds: &Bounds<'_>,
) -> Result<()> {
    ensure!(body.len() <= bounds.max_body, "backend request body exceeds its bound");
    let mut head = format!("{method} {target} HTTP/1.1\r\n");
    for (name, value) in filter_request_headers(headers) {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str(&format!("content-length: {}\r\n", body.len()));
    head.push_str("connection: close\r\n\r\n");
    timeout(*bounds.idle, async {
        writer.write_all(head.as_bytes()).await?;
        if !body.is_empty() {
            writer.write_all(body).await?;
        }
        writer.flush().await
    })
    .await
    .map_err(|_| anyhow!("backend write timed out"))??;
    Ok(())
}

/// Read one complete backend response head under `bound`.
pub(super) async fn read_backend_head<R: AsyncBufReadExt + Unpin>(
    reader: &mut R,
    bound: Instant,
) -> Result<(String, u16, Vec<(String, String)>)> {
    let mut head = Vec::new();
    let mut line = Vec::new();
    loop {
        line.clear();
        let read = timeout_at(bound, reader.read_until(b'\n', &mut line))
            .await
            .map_err(|_| anyhow!("backend header read timed out"))??;
        ensure!(read > 0, "backend closed before any response");
        ensure!(head.len() + line.len() <= MAX_HEAD_BYTES, "backend response head exceeds its bound");
        if line == b"\r\n" || line == b"\n" {
            break;
        }
        head.extend_from_slice(&line);
    }
    let text = String::from_utf8(head).map_err(|_| anyhow!("backend response head is not ASCII"))?;
    let mut lines = text.split("\r\n");
    let status_line = lines.next().ok_or_else(|| anyhow!("backend response has no status line"))?;
    let mut fields = status_line.split(' ');
    let (_version, Some(code)) = (fields.next(), fields.next()) else {
        bail!("backend status line is malformed");
    };
    let status: u16 = code.parse().map_err(|_| anyhow!("backend status code is invalid"))?;
    let mut headers = Vec::new();
    let mut lines = lines.peekable();
    while let Some(line) = lines.next() {
        // `read_backend_head` stops before the empty terminator line, so the
        // last header still carries its CRLF: that one empty line is the
        // head's real terminator. Any other line without ':' is malformed.
        if line.is_empty() {
            ensure!(lines.peek().is_none(), "backend header is malformed");
            break;
        }
        let (name, value) = line.split_once(':').ok_or_else(|| anyhow!("backend header is malformed"))?;
        headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
    }
    Ok((status_line.to_owned(), status, headers))
}

/// Read the complete backend body under `max_response`. A `Content-Length`
/// response that ends early is returned with `truncated = true` instead of being
/// trusted; a chunked body is decoded with the same bound.
pub(super) async fn read_backend<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    headers: &[(String, String)],
    bounds: &Bounds<'_>,
) -> Result<(Vec<u8>, bool)> {
    if chunked(headers) {
        return read_chunked(reader, bounds).await;
    }
    let mut buffer = vec![0u8; 64 * 1024];
    if let Some(value) = header(headers, "content-length") {
        let length: usize = value.parse().map_err(|_| anyhow!("backend content length is invalid"))?;
        ensure!(length <= bounds.max_response, "backend response exceeds its bound");
        let mut body = Vec::with_capacity(length);
        while body.len() < length {
            let want = (length - body.len()).min(buffer.len());
            let read = read_bounded(reader, &mut buffer[..want], *bounds.idle).await?;
            if read == 0 {
                return Ok((body, true));
            }
            body.extend_from_slice(&buffer[..read]);
        }
        return Ok((body, false));
    }
    let mut body = Vec::new();
    loop {
        let read = read_bounded(reader, &mut buffer, *bounds.idle).await?;
        if read == 0 {
            return Ok((body, false));
        }
        ensure!(body.len() + read <= bounds.max_response, "backend response exceeds its bound");
        body.extend_from_slice(&buffer[..read]);
    }
}

async fn read_chunked<R: AsyncRead + Unpin>(reader: &mut R, bounds: &Bounds<'_>) -> Result<(Vec<u8>, bool)> {
    let mut body = Vec::new();
    loop {
        let size_line = read_line(reader, *bounds.idle, bounds.max_body).await?;
        let Some(size_line) = size_line else { return Ok((body, true)) };
        let size_line = std::str::from_utf8(&size_line).map_err(|_| anyhow!("backend chunk size is not ASCII"))?;
        let size_text = size_line.trim().split(';').next().unwrap_or("");
        let size = usize::from_str_radix(size_text, 16).map_err(|_| anyhow!("backend chunk size is invalid"))?;
        if size == 0 {
            loop {
                match read_line(reader, *bounds.idle, MAX_HEAD_BYTES).await? {
                    Some(trailer) if !trailer.iter().all(u8::is_ascii_whitespace) => continue,
                    _ => return Ok((body, false)),
                }
            }
        }
        ensure!(body.len() + size <= bounds.max_response, "backend response exceeds its bound");
        let mut chunk = vec![0u8; size];
        timeout(*bounds.idle, reader.read_exact(&mut chunk))
            .await
            .map_err(|_| anyhow!("backend chunk read timed out"))?
            .map_err(|_| anyhow!("backend chunk is truncated"))?;
        body.extend_from_slice(&chunk);
        let mut terminator = [0u8; 2];
        timeout(*bounds.idle, reader.read_exact(&mut terminator))
            .await
            .map_err(|_| anyhow!("backend chunk terminator read timed out"))?
            .map_err(|_| anyhow!("backend chunk terminator is truncated"))?;
        ensure!(&terminator == b"\r\n", "backend chunk terminator is invalid");
    }
}

/// One CRLF/LF-terminated line of at most `limit` bytes; `None` on clean EOF.
async fn read_line<R: AsyncRead + Unpin>(reader: &mut R, idle: Duration, limit: usize) -> Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        let read = read_bounded(reader, &mut byte, idle).await?;
        if read == 0 {
            ensure!(line.is_empty(), "backend line ended early");
            return Ok(None);
        }
        line.push(byte[0]);
        ensure!(line.len() <= limit, "backend line exceeds its bound");
        if line.ends_with(b"\n") {
            return Ok(Some(line));
        }
    }
}

async fn read_bounded<R: AsyncRead + Unpin>(reader: &mut R, buffer: &mut [u8], idle: Duration) -> Result<usize> {
    timeout(idle, reader.read(buffer)).await.map_err(|_| anyhow!("backend read timed out"))?.map_err(Into::into)
}

/// End-to-end headers of one backend response, minus the hop-by-hop ones and
/// the framing the proxy recomputes: connection management, `Content-Length`
/// (recomputed from the decoded body) and `Transfer-Encoding` (bodies are
/// forwarded decoded and delimited by `Connection: close`). Retained headers
/// keep their order and value verbatim, so `WWW-Authenticate`, `Content-Type`
/// and `X-Rootyard-Operation` reach the Git client exactly as the service sent
/// them.
pub(super) fn response_headers(headers: &[(String, String)]) -> Vec<(String, String)> {
    let mut hop_by_hop = vec![
        "connection".to_owned(),
        "proxy-connection".to_owned(),
        "keep-alive".to_owned(),
        "transfer-encoding".to_owned(),
        "content-length".to_owned(),
        "te".to_owned(),
        "trailer".to_owned(),
        "upgrade".to_owned(),
    ];
    // Headers listed by `Connection` are themselves hop-by-hop.
    for (name, value) in headers {
        if name == "connection" {
            hop_by_hop.extend(
                value.split(',').map(|token| token.trim().to_ascii_lowercase()).filter(|token| !token.is_empty()),
            );
        }
    }
    headers.iter().filter(|(name, _)| !hop_by_hop.iter().any(|hop| hop == name)).cloned().collect()
}

/// Write one client response: the status line, the backend end-to-end headers,
/// the recomputed `Content-Length` and `Connection: close`.
pub(super) async fn write_reply<W: AsyncWrite + Unpin>(
    writer: &mut W,
    idle: Duration,
    status: u16,
    reason: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Result<()> {
    let mut head = format!("HTTP/1.1 {status} {reason}\r\n");
    for (name, value) in response_headers(headers) {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str(&format!("Content-Length: {}\r\nConnection: close\r\n\r\n", body.len()));
    timeout(idle, async {
        writer.write_all(head.as_bytes()).await?;
        writer.write_all(body).await?;
        writer.flush().await
    })
    .await
    .map_err(|_| anyhow!("client write timed out"))??;
    Ok(())
}

/// One request on a fresh connection to `address` with the caller's exact
/// method, target, headers and body; returns the service's complete response.
/// Used by the proxy for its own exchange and by start-up diagnostics.
pub(super) async fn exchange(
    address: std::net::SocketAddr,
    bounds: &Bounds<'_>,
    method: &str,
    target: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Result<BackendTraffic> {
    let stream = timeout(*bounds.idle, tokio::net::TcpStream::connect(address))
        .await
        .map_err(|_| anyhow!("backend connect timed out"))??;
    let _ = stream.set_nodelay(true);
    let (read, mut writer) = stream.into_split();
    let mut reader = BufReader::with_capacity(64 * 1024, read);
    write_request(&mut writer, method, target, headers, body, bounds).await?;
    let (_, status, response_headers) = read_backend_head(&mut reader, Instant::now() + *bounds.idle).await?;
    let (body, truncated) = read_backend(&mut reader, &response_headers, bounds).await?;
    Ok(BackendTraffic { status, headers: response_headers, body, truncated })
}

/// Decode the pkt-line payloads of a body up to and including its first flush
/// (`0000`). Anything malformed is an error, never a partial success.
pub(super) fn pkt_lines_until_flush(body: &[u8]) -> Result<(Vec<Vec<u8>>, usize)> {
    let mut position = 0usize;
    let mut lines = Vec::new();
    loop {
        ensure!(position + 4 <= body.len(), "pkt-line stream is truncated");
        let length = usize::from_str_radix(std::str::from_utf8(&body[position..position + 4])?, 16)
            .map_err(|_| anyhow!("pkt-line length is invalid"))?;
        if length == 0 {
            return Ok((lines, position + 4));
        }
        ensure!(length >= 4 && position + length <= body.len(), "pkt-line is malformed");
        lines.push(body[position + 4..position + length].to_vec());
        position += length;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn read(raw: &[u8]) -> Result<(String, u16, Vec<(String, String)>)> {
        let mut reader = BufReader::new(raw);
        read_backend_head(&mut reader, Instant::now() + Duration::from_secs(5)).await
    }

    /// A real backend head as Git's smart HTTP server sends it: status line,
    /// headers and the terminating CRLF that `read_backend_head` consumes.
    const REAL: &[u8] = b"HTTP/1.1 200 OK\r\n\
        Server: Apache\r\n\
        Expires: Fri, 01 Jan 1980 00:00:00 GMT\r\n\
        Pragma: no-cache\r\n\
        Cache-Control: no-cache, max-age=0, must-revalidate\r\n\
        Content-Type: application/x-git-upload-pack-result\r\n\
        Transfer-Encoding: chunked\r\n\
        \r\n";

    #[tokio::test]
    async fn real_response_head_with_terminating_crlf_parses() {
        let (status_line, status, headers) = read(REAL).await.unwrap();
        assert_eq!(status_line, "HTTP/1.1 200 OK");
        assert_eq!(status, 200);
        assert_eq!(headers.len(), 6);
        assert_eq!(header(&headers, "content-type"), Some("application/x-git-upload-pack-result"));
        assert_eq!(header(&headers, "cache-control"), Some("no-cache, max-age=0, must-revalidate"));
        assert_eq!(header(&headers, "transfer-encoding"), Some("chunked"));
        assert!(headers.iter().all(|(name, _)| name == &name.to_ascii_lowercase()));
    }

    #[tokio::test]
    async fn other_real_statuses_parse() {
        let (_, status, headers) = read(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n").await.unwrap();
        assert_eq!(status, 404);
        assert_eq!(header(&headers, "content-length"), Some("0"));
        let (_, status, headers) =
            read(b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"x\"\r\n\r\n").await.unwrap();
        assert_eq!(status, 401);
        assert_eq!(header(&headers, "www-authenticate"), Some("Basic realm=\"x\""));
        let (_, status, headers) = read(b"HTTP/1.1 204 No Content\r\n\r\n").await.unwrap();
        assert_eq!(status, 204);
        assert!(headers.is_empty());
    }

    #[tokio::test]
    async fn header_line_without_colon_is_rejected() {
        let bad: [&[u8]; 3] = [
            b"HTTP/1.1 200 OK\r\nno-colon-here\r\nContent-Type: x\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Type: x\r\nno-colon-here\r\n\r\n",
            // Two empty lines: only the final one is the terminator.
            b"HTTP/1.1 200 OK\r\nContent-Type: x\r\n\r\nY: z\r\n\r\n",
        ];
        for raw in bad {
            let error = read(raw).await.unwrap_err().to_string();
            assert_eq!(error, "backend header is malformed", "{raw:?}");
        }
    }

    /// One backend response (head followed by its body) as the proxy writes it
    /// to a stock Git client: the codec round trip from the wire bytes to the
    /// bytes on the client socket.
    async fn reply(backend: &[u8]) -> (u16, Vec<(String, String)>, Vec<u8>) {
        let mut reader = backend;
        let (_, status, headers) =
            read_backend_head(&mut reader, Instant::now() + Duration::from_secs(5)).await.unwrap();
        let (decoded, truncated) = read_backend(
            &mut reader,
            &headers,
            &Bounds { max_body: 1024, max_response: 1024, idle: &Duration::from_secs(5) },
        )
        .await
        .unwrap();
        assert!(!truncated);
        let mut written = Vec::new();
        write_reply(&mut written, Duration::from_secs(5), status, "OK", &headers, &decoded).await.unwrap();
        let mut client = BufReader::new(written.as_slice());
        let (_, status, reply_headers) =
            read_backend_head(&mut client, Instant::now() + Duration::from_secs(5)).await.unwrap();
        let (reply_body, truncated) = read_backend(
            &mut client,
            &reply_headers,
            &Bounds { max_body: 1024, max_response: 1024, idle: &Duration::from_secs(5) },
        )
        .await
        .unwrap();
        assert!(!truncated);
        (status, reply_headers, reply_body)
    }

    #[tokio::test]
    async fn reply_preserves_401_challenge_content_type_and_operation() {
        let backend: &[u8] = b"HTTP/1.1 401 Unauthorized\r\n\
            WWW-Authenticate: Basic realm=\"rootyard\"\r\n\
            Content-Type: application/x-git-receive-pack-result\r\n\
            X-Rootyard-Operation: 7d8c1f0e-2b3a-4c5d-8e9f-0a1b2c3d4e5f\r\n\
            Cache-Control: no-cache\r\n\
            Content-Length: 12\r\n\
            \r\n\
            challenged!!";
        let (status, headers, body) = reply(backend).await;
        assert_eq!(status, 401);
        assert_eq!(body, b"challenged!!");
        assert_eq!(header(&headers, "www-authenticate"), Some("Basic realm=\"rootyard\""));
        assert_eq!(header(&headers, "content-type"), Some("application/x-git-receive-pack-result"));
        assert_eq!(header(&headers, "x-rootyard-operation"), Some("7d8c1f0e-2b3a-4c5d-8e9f-0a1b2c3d4e5f"));
        assert_eq!(header(&headers, "cache-control"), Some("no-cache"));
    }

    #[tokio::test]
    async fn reply_preserves_git_content_type_and_operation() {
        let backend: &[u8] = b"HTTP/1.1 200 OK\r\n\
            Content-Type: application/x-git-receive-pack-advertisement\r\n\
            X-Rootyard-Operation: 0d9e4c7a-1f2b-4a3c-9b8d-6e5f4a3b2c1d\r\n\
            Content-Length: 4\r\n\
            \r\n\
            000d";
        let (status, headers, body) = reply(backend).await;
        assert_eq!(status, 200);
        assert_eq!(body, b"000d");
        assert_eq!(header(&headers, "content-type"), Some("application/x-git-receive-pack-advertisement"));
        assert_eq!(header(&headers, "x-rootyard-operation"), Some("0d9e4c7a-1f2b-4a3c-9b8d-6e5f4a3b2c1d"));
        assert_eq!(header(&headers, "content-length"), Some("4"));
    }

    #[tokio::test]
    async fn reply_recomputes_length_and_drops_hop_by_hop_headers() {
        let backend = [
            "HTTP/1.1 200 OK",
            "Content-Type: application/x-git-receive-pack-result",
            "Transfer-Encoding: chunked",
            "Connection: keep-alive, X-Hop, close",
            "X-Hop: stripped",
            "Keep-Alive: timeout=5",
            "",
            // Two exact chunks (sizes in hex); no chunk boundary ends on a CR,
            // because `read_backend` stops a chunk read at a CR.
            "4",
            "chun",
            "6",
            "ked-bo",
            "2",
            "dy",
            "0",
            "",
            "",
        ]
        .join("\r\n")
        .into_bytes();
        let (status, headers, body) = reply(&backend).await;
        assert_eq!(status, 200);
        assert_eq!(body, b"chunked-body");
        assert_eq!(header(&headers, "content-length"), Some("12"));
        assert_eq!(header(&headers, "connection"), Some("close"));
        assert_eq!(header(&headers, "content-type"), Some("application/x-git-receive-pack-result"));
        for hop in ["transfer-encoding", "x-hop", "keep-alive"] {
            assert_eq!(header(&headers, hop), None, "{hop} must not reach the client");
        }
        assert_eq!(headers.iter().filter(|(name, _)| name == "content-length").count(), 1);
    }

    #[tokio::test]
    async fn synthetic_reply_has_no_backend_headers() {
        let mut written = Vec::new();
        write_reply(&mut written, Duration::from_secs(5), 502, "Bad Gateway", &[], b"").await.unwrap();
        assert_eq!(written, b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    }

    #[tokio::test]
    async fn malformed_status_lines_are_rejected() {
        assert_eq!(read(b"HTTP/1.1\r\n\r\n").await.unwrap_err().to_string(), "backend status line is malformed");
        assert_eq!(read(b"HTTP/1.1 abc OK\r\n\r\n").await.unwrap_err().to_string(), "backend status code is invalid");
        assert_eq!(read(b"").await.unwrap_err().to_string(), "backend closed before any response");
    }
}
