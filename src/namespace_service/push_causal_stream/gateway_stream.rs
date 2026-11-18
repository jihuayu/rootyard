//! Shared-deadline HTTP `git-receive-pack` pkt-line + pack stream spooler (#183).
//!
//! Enforces ONE total `deadline: tokio::time::Instant` across both the pkt-line
//! command section (up through the `0000` flush) and the trailing `PACK` stream,
//! bounding both compressed wire bytes and decoded staging bytes without buffering
//! packs in memory.

use std::io;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::{Context, Poll};

use async_compression::tokio::bufread::GzipDecoder;
use axum::body::{Body, BodyDataStream};
use bytes::Bytes;
use futures_util::Stream;
use tokio::fs::OpenOptions;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader, ReadBuf};
use tokio::time::{Instant, timeout_at};

use crate::blob_git_gateway::GatewayError;

use super::types::STREAM_CHUNK_BYTES;

const MAX_COMMAND_BYTES: usize = 128 * 1024;
const MAX_PKT_LINE_BYTES: usize = 65_520;

/// Stream an HTTP `git-receive-pack` body (identity or single-member gzip) into `request_path`
/// under a single shared `deadline`, validating pkt-line framing live as bytes arrive so a
/// slowloris command-phase stall fails closed on `deadline` before `0000` flush.
pub async fn spool_receive_stream_shared_deadline(
    body: Body,
    request_path: &Path,
    wire_max: u64,
    expanded_max: u64,
    encoding: Option<&str>,
    deadline: Instant,
) -> Result<(u64, Vec<u8>), GatewayError> {
    let gzip = decode_encoding(encoding)?;
    let wire_exceeded = Arc::new(AtomicBool::new(false));
    let body_reader = BodyStreamReader::new(body.into_data_stream(), wire_max, wire_exceeded.clone());
    let mut decoder: Box<dyn AsyncRead + Unpin + Send> = if gzip {
        let mut gz = GzipDecoder::new(BufReader::with_capacity(STREAM_CHUNK_BYTES, body_reader));
        gz.multiple_members(false);
        Box::new(gz)
    } else {
        Box::new(BufReader::with_capacity(STREAM_CHUNK_BYTES, body_reader))
    };

    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        opts.mode(0o600);
    }
    let mut file = opts.open(request_path).await.map_err(|_| GatewayError::Internal("could not stage the request"))?;

    let mut prefix = Vec::new();
    let mut total_expanded = 0u64;

    loop {
        let mut hdr = [0u8; 4];
        match read_exact_or_eof(decoder.as_mut(), &mut hdr, deadline, gzip, &wire_exceeded).await? {
            HeaderRead::CleanEof => {
                if total_expanded < 4 {
                    return Err(GatewayError::BadRequest("push request is truncated"));
                }
                return Err(GatewayError::BadRequest("truncated push command pkt-line"));
            }
            HeaderRead::PartialEof => {
                if total_expanded < 4 {
                    return Err(GatewayError::BadRequest("push request is truncated"));
                }
                return Err(GatewayError::BadRequest("truncated push command pkt-line"));
            }
            HeaderRead::Full => {}
        }
        total_expanded = total_expanded.checked_add(4).ok_or(GatewayError::TooLarge)?;
        if total_expanded > expanded_max {
            return Err(GatewayError::TooLarge);
        }
        prefix.extend_from_slice(&hdr);
        write_bounded(&mut file, &hdr, deadline).await?;

        let length = std::str::from_utf8(&hdr)
            .ok()
            .filter(|s| s.bytes().all(|b| b.is_ascii_hexdigit()))
            .and_then(|s| usize::from_str_radix(s, 16).ok())
            .ok_or(GatewayError::BadRequest("invalid push command pkt-line length"))?;
        if length == 0 {
            break;
        }
        if !(4..=MAX_PKT_LINE_BYTES).contains(&length) {
            return Err(GatewayError::BadRequest("invalid push command pkt-line length"));
        }
        let payload_len = length - 4;
        if prefix.len().saturating_add(payload_len) > MAX_COMMAND_BYTES {
            return Err(GatewayError::BadRequest("push command section exceeds its byte bound"));
        }
        total_expanded = total_expanded.checked_add(payload_len as u64).ok_or(GatewayError::TooLarge)?;
        if total_expanded > expanded_max {
            return Err(GatewayError::TooLarge);
        }
        let mut payload = vec![0u8; payload_len];
        read_payload_exact(decoder.as_mut(), &mut payload, deadline, gzip, &wire_exceeded).await?;
        prefix.extend_from_slice(&payload);
        write_bounded(&mut file, &payload, deadline).await?;
    }

    let mut chunk_buf = vec![0u8; STREAM_CHUNK_BYTES];
    loop {
        let n = match timeout_at(deadline, decoder.read(&mut chunk_buf)).await {
            Ok(Ok(n)) => n,
            Ok(Err(_)) => return Err(map_stream_io_err(gzip, &wire_exceeded, "request body could not be read")),
            Err(_) => return Err(GatewayError::Timeout),
        };
        if n == 0 {
            break;
        }
        if wire_exceeded.load(Ordering::Acquire) {
            return Err(GatewayError::TooLarge);
        }
        total_expanded = total_expanded.checked_add(n as u64).ok_or(GatewayError::TooLarge)?;
        if total_expanded > expanded_max {
            return Err(GatewayError::TooLarge);
        }
        write_bounded(&mut file, &chunk_buf[..n], deadline).await?;
    }

    if wire_exceeded.load(Ordering::Acquire) {
        return Err(GatewayError::TooLarge);
    }
    timeout_at(deadline, file.flush())
        .await
        .map_err(|_| GatewayError::Timeout)?
        .map_err(|_| GatewayError::Internal("could not stage the request"))?;
    timeout_at(deadline, file.sync_all())
        .await
        .map_err(|_| GatewayError::Timeout)?
        .map_err(|_| GatewayError::Internal("could not stage the request"))?;

    Ok((total_expanded, prefix))
}

enum HeaderRead {
    CleanEof,
    PartialEof,
    Full,
}

async fn read_exact_or_eof<R: AsyncRead + Unpin + ?Sized>(
    reader: &mut R,
    buf: &mut [u8; 4],
    deadline: Instant,
    gzip: bool,
    wire_exceeded: &Arc<AtomicBool>,
) -> Result<HeaderRead, GatewayError> {
    let mut filled = 0usize;
    while filled < 4 {
        let n = match timeout_at(deadline, reader.read(&mut buf[filled..])).await {
            Ok(Ok(n)) => n,
            Ok(Err(_)) => return Err(map_stream_io_err(gzip, wire_exceeded, "request body could not be read")),
            Err(_) => return Err(GatewayError::Timeout),
        };
        if wire_exceeded.load(Ordering::Acquire) {
            return Err(GatewayError::TooLarge);
        }
        if n == 0 {
            return Ok(if filled == 0 { HeaderRead::CleanEof } else { HeaderRead::PartialEof });
        }
        filled += n;
    }
    Ok(HeaderRead::Full)
}

async fn read_payload_exact<R: AsyncRead + Unpin + ?Sized>(
    reader: &mut R,
    buf: &mut [u8],
    deadline: Instant,
    gzip: bool,
    wire_exceeded: &Arc<AtomicBool>,
) -> Result<(), GatewayError> {
    let mut filled = 0usize;
    while filled < buf.len() {
        let n = match timeout_at(deadline, reader.read(&mut buf[filled..])).await {
            Ok(Ok(n)) => n,
            Ok(Err(_)) => return Err(map_stream_io_err(gzip, wire_exceeded, "request body could not be read")),
            Err(_) => return Err(GatewayError::Timeout),
        };
        if wire_exceeded.load(Ordering::Acquire) {
            return Err(GatewayError::TooLarge);
        }
        if n == 0 {
            return Err(GatewayError::BadRequest("truncated push command pkt-line"));
        }
        filled += n;
    }
    Ok(())
}

async fn write_bounded(file: &mut tokio::fs::File, bytes: &[u8], deadline: Instant) -> Result<(), GatewayError> {
    timeout_at(deadline, file.write_all(bytes))
        .await
        .map_err(|_| GatewayError::Timeout)?
        .map_err(|_| GatewayError::Internal("could not stage the request"))
}

fn map_stream_io_err(gzip: bool, wire_exceeded: &Arc<AtomicBool>, fallback: &'static str) -> GatewayError {
    if wire_exceeded.load(Ordering::Acquire) {
        GatewayError::TooLarge
    } else if gzip {
        GatewayError::BadRequest("compressed Git request body is invalid")
    } else {
        GatewayError::BadRequest(fallback)
    }
}

fn decode_encoding(encoding: Option<&str>) -> Result<bool, GatewayError> {
    let Some(raw) = encoding else { return Ok(false) };
    let value = raw.trim();
    if value.is_empty() || value.eq_ignore_ascii_case("identity") {
        return Ok(false);
    }
    if value.eq_ignore_ascii_case("gzip") || value.eq_ignore_ascii_case("x-gzip") {
        return Ok(true);
    }
    Err(GatewayError::BadRequest("unsupported Git request content encoding"))
}

struct BodyStreamReader {
    stream: BodyDataStream,
    current: Bytes,
    wire_bytes: AtomicU64,
    wire_max: u64,
    exceeded: Arc<AtomicBool>,
}

impl BodyStreamReader {
    fn new(stream: BodyDataStream, wire_max: u64, exceeded: Arc<AtomicBool>) -> Self {
        Self { stream, current: Bytes::new(), wire_bytes: AtomicU64::new(0), wire_max, exceeded }
    }
}

impl AsyncRead for BodyStreamReader {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        while this.current.is_empty() {
            match Pin::new(&mut this.stream).poll_next(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(io::Error::other(e.to_string()))),
                Poll::Ready(Some(Ok(chunk))) => {
                    let prev = this.wire_bytes.fetch_add(chunk.len() as u64, Ordering::AcqRel);
                    if prev.checked_add(chunk.len() as u64).is_none_or(|next| next > this.wire_max) {
                        this.exceeded.store(true, Ordering::Release);
                        return Poll::Ready(Err(io::Error::other("wire request body exceeded limit")));
                    }
                    this.current = chunk;
                }
            }
        }
        let take = buf.remaining().min(this.current.len());
        buf.put_slice(&this.current.split_to(take));
        Poll::Ready(Ok(()))
    }
}
