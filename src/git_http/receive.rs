//! Bounded request decoding and exact receive-command admission.
use super::*;
use std::pin::Pin;

pub(super) struct PreparedInput {
    pub reader: Pin<Box<dyn tokio::io::AsyncRead + Send>>,
    pub commands: Option<protocol::ReceiveCommands>,
    pub gzipped: bool,
}

pub(super) async fn prepare(
    body: Body,
    headers: &HeaderMap,
    maximum: u64,
    metrics: Arc<crate::metrics::TransferCounters>,
    write: bool,
    oid_len: usize,
    deadline: Instant,
) -> Result<PreparedInput, Error> {
    let gzipped = headers.get(header::CONTENT_ENCODING).is_some_and(|v| v == "gzip" || v == "x-gzip");
    let mut wire_bytes = 0u64;
    let stream = body.into_data_stream().map(move |chunk| {
        let chunk = chunk.map_err(io::Error::other)?;
        wire_bytes = wire_bytes.saturating_add(chunk.len() as u64);
        metrics.add_received_bytes(chunk.len() as u64);
        if wire_bytes > maximum {
            return Err(io::Error::other("request wire size limit exceeded"));
        }
        Ok(chunk)
    });
    let reader = tokio_util::io::StreamReader::new(stream);
    let mut reader: Pin<Box<dyn tokio::io::AsyncRead + Send>> = if gzipped {
        let mut decoder = async_compression::tokio::bufread::GzipDecoder::new(BufReader::new(reader));
        decoder.multiple_members(true);
        Box::pin(decoder)
    } else {
        Box::pin(reader)
    };
    let commands = if write {
        Some(
            tokio::time::timeout_at(deadline, protocol::receive_commands(&mut reader, oid_len))
                .await
                .map_err(|_| Error::timeout())??,
        )
    } else {
        None
    };
    Ok(PreparedInput { reader, commands, gzipped })
}

pub(super) async fn write_input(
    mut prepared: PreparedInput,
    mut stdin: tokio::process::ChildStdin,
    maximum: u64,
) -> io::Result<()> {
    let prefix = prepared.commands.take().map(|commands| commands.bytes).unwrap_or_default();
    let mut decoded = prefix.len() as u64;
    if decoded > maximum {
        return Err(io::Error::other("decoded request size limit exceeded"));
    }
    stdin.write_all(&prefix).await?;
    let mut buf = [0u8; 32 * 1024];
    loop {
        let n = prepared.reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        decoded = decoded.saturating_add(n as u64);
        if decoded > maximum {
            return Err(io::Error::other("decoded request size limit exceeded"));
        }
        stdin.write_all(&buf[..n]).await?;
    }
    stdin.shutdown().await
}
