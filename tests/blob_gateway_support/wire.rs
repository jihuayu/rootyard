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

pub(super) fn parse_head(head: &[u8]) -> Result<(String, String, Vec<(String, String)>)> {
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
    for line in lines {
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

pub(super) async fn write_reply<W: AsyncWrite + Unpin>(
    writer: &mut W,
    idle: Duration,
    status: u16,
    reason: &str,
    body: &[u8],
) -> Result<()> {
    let head = format!("HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
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
