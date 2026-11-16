//! Bounded mTLS chunk streaming with Tokio mpsc backpressure, deadlines, and cancellation.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use openraft::LogId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tokio::time::{Instant, timeout_at};

use crate::cluster::{read_frame_bounded_async, write_frame_bounded_async};
use crate::{E, Res};

/// Maximum metadata proposal payload permitted in Raft log entries (256 KiB).
pub const MAX_RAFT_PROPOSAL_BYTES: usize = 256 * 1024;
/// Maximum payload bytes per streaming chunk frame (64 KiB).
pub const MAX_STREAM_FRAME_BYTES: usize = 64 * 1024;
/// Maximum cumulative payload bytes per streaming RPC response (4 MiB).
pub const MAX_STREAM_TOTAL_BYTES: usize = 4 * 1024 * 1024;
/// Default bounded Tokio mpsc channel depth per stream.
pub const DEFAULT_CHANNEL_CAPACITY: usize = 4;
/// Hard ceiling on mpsc channel depth per stream.
pub const MAX_CHANNEL_CAPACITY: usize = 16;
/// Maximum encoded wire JSON frame size for stream frames (`4x` raw + metadata slack).
pub const MAX_STREAM_WIRE_FRAME_BYTES: usize = 4 * MAX_STREAM_FRAME_BYTES + 8192;

/// Rejects large payloads, raw Git packfiles, and Blob data before entering the Raft WAL.
pub fn validate_raft_proposal_payload(payload: &[u8]) -> Res<()> {
    if payload.len() > MAX_RAFT_PROPOSAL_BYTES {
        return Err(E::Refused(format!(
            "raft proposal length {} exceeds metadata cap {MAX_RAFT_PROPOSAL_BYTES} (large bytes must go to Blob storage)",
            payload.len()
        )));
    }
    if payload.starts_with(b"PACK") || payload.starts_with(b"version https://git-lfs.github.com/spec/v1") {
        return Err(E::Refused(
            "raw Git pack or LFS object payload is forbidden in Raft proposals; store bytes in Blob store".into(),
        ));
    }
    Ok(())
}

/// Caller/server configuration bounding channel queue depth, frame bytes, total bytes, and deadlines.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamConfig {
    pub channel_capacity: usize,
    pub max_frame_bytes: usize,
    pub max_total_bytes: usize,
    pub write_deadline_ms: u64,
    pub stream_deadline_ms: u64,
}

impl Default for StreamConfig {
    fn default() -> Self {
        Self {
            channel_capacity: DEFAULT_CHANNEL_CAPACITY,
            max_frame_bytes: MAX_STREAM_FRAME_BYTES,
            max_total_bytes: MAX_STREAM_TOTAL_BYTES,
            write_deadline_ms: 1_500,
            stream_deadline_ms: 8_000,
        }
    }
}

impl StreamConfig {
    /// Enforces hard upper and lower limits so streams can never allocate unbounded queues or payloads.
    pub fn validate(&self) -> Res<()> {
        if self.channel_capacity == 0 || self.channel_capacity > MAX_CHANNEL_CAPACITY {
            return Err(E::Refused(format!(
                "invalid stream channel_capacity {} (expected 1..={MAX_CHANNEL_CAPACITY})",
                self.channel_capacity
            )));
        }
        if self.max_frame_bytes == 0 || self.max_frame_bytes > MAX_STREAM_FRAME_BYTES {
            return Err(E::Refused(format!(
                "invalid stream max_frame_bytes {} (expected 1..={MAX_STREAM_FRAME_BYTES})",
                self.max_frame_bytes
            )));
        }
        if self.max_total_bytes == 0 || self.max_total_bytes > MAX_STREAM_TOTAL_BYTES {
            return Err(E::Refused(format!(
                "invalid stream max_total_bytes {} (expected 1..={MAX_STREAM_TOTAL_BYTES})",
                self.max_total_bytes
            )));
        }
        if self.write_deadline_ms < 20 || self.write_deadline_ms > 30_000 {
            return Err(E::Refused(format!("invalid stream write_deadline_ms {}", self.write_deadline_ms)));
        }
        if self.stream_deadline_ms < self.write_deadline_ms || self.stream_deadline_ms > 60_000 {
            return Err(E::Refused(format!("invalid stream stream_deadline_ms {}", self.stream_deadline_ms)));
        }
        Ok(())
    }
}

/// Server-to-client bounded stream frames carried over mTLS.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum StreamFrame {
    Header { stream_id: u64, planned_chunks: u64, planned_bytes: u64, read_log_id: Option<LogId<u64>>, window: u64 },
    Chunk { seq: u64, data: Vec<u8> },
    End { total_chunks: u64, total_bytes: u64, sha256_hex: String },
    Cancel { reason: String },
}

/// Client-to-server backpressure window credit frame.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamCredit {
    pub granted_chunks: u64,
}

/// Live and peak buffered-byte telemetry proving bounded allocation and deterministic drop cleanup.
#[derive(Debug, Default)]
pub struct BufferedByteTracker {
    live_bytes: AtomicUsize,
    peak_bytes: AtomicUsize,
    produced_chunks: AtomicU64,
    cancelled: AtomicBool,
}

/// Point-in-time snapshot of stream buffer accounting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrackerSnapshot {
    pub live_bytes: usize,
    pub peak_bytes: usize,
    pub produced_chunks: u64,
    pub cancelled: bool,
}

impl BufferedByteTracker {
    /// Creates an empty zeroed tracker.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn snapshot(&self) -> TrackerSnapshot {
        TrackerSnapshot {
            live_bytes: self.live_bytes.load(Ordering::SeqCst),
            peak_bytes: self.peak_bytes.load(Ordering::SeqCst),
            produced_chunks: self.produced_chunks.load(Ordering::SeqCst),
            cancelled: self.cancelled.load(Ordering::SeqCst),
        }
    }

    pub fn mark_cancelled(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    fn alloc(self: &Arc<Self>, len: usize) {
        self.produced_chunks.fetch_add(1, Ordering::SeqCst);
        let now = self.live_bytes.fetch_add(len, Ordering::SeqCst) + len;
        let _ = self.peak_bytes.fetch_max(now, Ordering::SeqCst);
    }

    fn free(&self, len: usize) {
        self.live_bytes.fetch_sub(len, Ordering::SeqCst);
    }
}

/// RAII-accounted payload chunk stored inside the bounded `mpsc` channel.
pub struct TrackedChunk {
    data: Vec<u8>,
    tracker: Arc<BufferedByteTracker>,
}

impl TrackedChunk {
    /// Wraps `data`, immediately adding `data.len()` to tracked live and peak buffered bytes.
    pub fn new(data: Vec<u8>, tracker: Arc<BufferedByteTracker>) -> Self {
        tracker.alloc(data.len());
        Self { data, tracker }
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

impl Drop for TrackedChunk {
    fn drop(&mut self) {
        self.tracker.free(self.data.len());
    }
}

/// Metadata identifying a planned bounded stream before chunk production begins.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamPlan {
    pub stream_id: u64,
    pub read_log_id: Option<LogId<u64>>,
    pub planned_chunks: u64,
    pub planned_bytes: u64,
}

/// Server-side stream completion summary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamServerOutcome {
    pub sent_chunks: u64,
    pub sent_bytes: u64,
    pub cancelled: bool,
    pub cancel_reason: Option<String>,
}

/// Client-side verified stream completion result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceivedStream {
    pub stream_id: u64,
    pub read_log_id: Option<LogId<u64>>,
    pub total_chunks: u64,
    pub total_bytes: u64,
    pub sha256_hex: String,
    pub chunks: Vec<Vec<u8>>,
}

/// Streams chunks from a bounded `mpsc::Receiver` with credit-window backpressure and cancellation.
pub async fn serve_bounded_stream<S>(
    stream: &mut S,
    plan: &StreamPlan,
    config: &StreamConfig,
    tracker: Arc<BufferedByteTracker>,
    mut rx: mpsc::Receiver<TrackedChunk>,
) -> StreamServerOutcome
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if let Err(e) = config.validate() {
        tracker.mark_cancelled();
        drop(rx);
        return abort_stream(stream, &e.to_string(), 0, 0).await;
    }
    if plan.planned_bytes > config.max_total_bytes as u64 {
        tracker.mark_cancelled();
        drop(rx);
        return abort_stream(stream, "planned stream bytes exceed max_total_bytes cap", 0, 0).await;
    }

    let overall_deadline = Instant::now() + Duration::from_millis(config.stream_deadline_ms);
    let step_dur = Duration::from_millis(config.write_deadline_ms);
    let window = config.channel_capacity as u64;
    let header = StreamFrame::Header {
        stream_id: plan.stream_id,
        planned_chunks: plan.planned_chunks,
        planned_bytes: plan.planned_bytes,
        read_log_id: plan.read_log_id,
        window,
    };
    if let Err(reason) = write_with_budget(stream, &header, step_dur, overall_deadline).await {
        tracker.mark_cancelled();
        drop(rx);
        return StreamServerOutcome { sent_chunks: 0, sent_bytes: 0, cancelled: true, cancel_reason: Some(reason) };
    }

    let mut credits = window;
    let mut seq = 0_u64;
    let mut sent_bytes = 0_u64;
    let mut hasher = Sha256::new();

    loop {
        while credits == 0 {
            match await_credit(stream, step_dur, overall_deadline).await {
                Ok(grant) if grant > 0 => credits = credits.saturating_add(grant.min(window * 2)),
                Ok(_) => {
                    tracker.mark_cancelled();
                    drop(rx);
                    return abort_stream(stream, "zero stream credit rejected", seq, sent_bytes).await;
                }
                Err(reason) => {
                    tracker.mark_cancelled();
                    drop(rx);
                    return abort_stream(stream, &reason, seq, sent_bytes).await;
                }
            }
        }

        let Some(chunk) = (match timeout_at(overall_deadline, rx.recv()).await {
            Ok(item) => item,
            Err(_) => {
                tracker.mark_cancelled();
                drop(rx);
                return abort_stream(stream, "stream deadline exceeded awaiting producer", seq, sent_bytes).await;
            }
        }) else {
            break;
        };

        let bytes = chunk.data();
        if bytes.len() > config.max_frame_bytes {
            tracker.mark_cancelled();
            drop(chunk);
            drop(rx);
            return abort_stream(stream, "chunk exceeds max_frame_bytes cap", seq, sent_bytes).await;
        }
        let next_total = sent_bytes.saturating_add(bytes.len() as u64);
        if next_total > config.max_total_bytes as u64 {
            tracker.mark_cancelled();
            drop(chunk);
            drop(rx);
            return abort_stream(stream, "stream exceeds max_total_bytes cap", seq, sent_bytes).await;
        }

        hasher.update(bytes);
        let frame = StreamFrame::Chunk { seq, data: bytes.to_vec() };
        drop(chunk);
        if let Err(reason) = write_with_budget(stream, &frame, step_dur, overall_deadline).await {
            tracker.mark_cancelled();
            drop(rx);
            return StreamServerOutcome { sent_chunks: seq, sent_bytes, cancelled: true, cancel_reason: Some(reason) };
        }
        seq += 1;
        sent_bytes = next_total;
        credits -= 1;
    }

    let digest: [u8; 32] = hasher.finalize().into();
    let end = StreamFrame::End { total_chunks: seq, total_bytes: sent_bytes, sha256_hex: hex_digest(&digest) };
    if let Err(reason) = write_with_budget(stream, &end, step_dur, overall_deadline).await {
        tracker.mark_cancelled();
        return StreamServerOutcome { sent_chunks: seq, sent_bytes, cancelled: true, cancel_reason: Some(reason) };
    }
    StreamServerOutcome { sent_chunks: seq, sent_bytes, cancelled: false, cancel_reason: None }
}

/// Reads and verifies all bounded stream frames on the client, sending credits smoothly when healthy.
pub async fn read_stream_bounded<S>(
    stream: &mut S,
    config: &StreamConfig,
    chunk_delay: Option<Duration>,
) -> Res<ReceivedStream>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    config.validate()?;
    let overall_deadline = Instant::now() + Duration::from_millis(config.stream_deadline_ms);
    let step_dur = Duration::from_millis(config.write_deadline_ms);

    let header = read_frame_with_budget::<_, StreamFrame>(stream, step_dur, overall_deadline).await?;
    let (stream_id, read_log_id, window) = match header {
        StreamFrame::Header { stream_id, planned_bytes, read_log_id, window, .. } => {
            if planned_bytes > config.max_total_bytes as u64 {
                return Err(E::Refused(format!("stream planned_bytes {planned_bytes} exceeds cap")));
            }
            (stream_id, read_log_id, window.max(1))
        }
        StreamFrame::Cancel { reason } => return Err(E::Refused(format!("stream cancelled: {reason}"))),
        other => return Err(E::Codec(format!("unexpected stream header frame: {other:?}"))),
    };

    let mut chunks = Vec::new();
    let mut expected_seq = 0_u64;
    let mut total_bytes = 0_u64;
    let mut window_left = window;
    let mut hasher = Sha256::new();

    loop {
        if let Some(delay) = chunk_delay {
            tokio::time::sleep(delay).await;
        }
        let frame = read_frame_with_budget::<_, StreamFrame>(stream, step_dur, overall_deadline).await?;
        match frame {
            StreamFrame::Chunk { seq, data } => {
                if seq != expected_seq {
                    return Err(E::Codec(format!("out-of-order stream chunk {seq}, expected {expected_seq}")));
                }
                if data.len() > config.max_frame_bytes {
                    return Err(E::Refused(format!("stream chunk {} exceeds max_frame_bytes", data.len())));
                }
                total_bytes = total_bytes
                    .checked_add(data.len() as u64)
                    .filter(|&sum| sum <= config.max_total_bytes as u64)
                    .ok_or_else(|| E::Refused("received stream exceeded max_total_bytes".into()))?;
                hasher.update(&data);
                chunks.push(data);
                expected_seq += 1;
                window_left = window_left.saturating_sub(1);
                if window_left == 0 {
                    let credit = StreamCredit { granted_chunks: window };
                    write_with_budget(stream, &credit, step_dur, overall_deadline)
                        .await
                        .map_err(|r| E::Refused(format!("failed sending stream credit: {r}")))?;
                    window_left = window;
                }
            }
            StreamFrame::End { total_chunks, total_bytes: reported_bytes, sha256_hex } => {
                if total_chunks != expected_seq || reported_bytes != total_bytes {
                    return Err(E::Codec("stream end counts mismatch received chunks".into()));
                }
                let actual = hex_digest(&hasher.finalize());
                if actual != sha256_hex {
                    return Err(E::Codec("stream sha256 checksum mismatch".into()));
                }
                return Ok(ReceivedStream { stream_id, read_log_id, total_chunks, total_bytes, sha256_hex, chunks });
            }
            StreamFrame::Cancel { reason } => return Err(E::Refused(format!("stream cancelled: {reason}"))),
            StreamFrame::Header { .. } => return Err(E::Codec("duplicate stream header".into())),
        }
    }
}

async fn write_with_budget<S, T>(stream: &mut S, value: &T, step: Duration, overall: Instant) -> Result<(), String>
where
    S: AsyncWrite + Unpin,
    T: Serialize,
{
    let step_deadline = (Instant::now() + step).min(overall);
    match timeout_at(step_deadline, write_frame_bounded_async(stream, value, MAX_STREAM_WIRE_FRAME_BYTES)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(format!("stream write failed: {e}")),
        Err(_) => Err("stream write deadline exceeded (slow consumer)".into()),
    }
}

async fn await_credit<S>(stream: &mut S, step: Duration, overall: Instant) -> Result<u64, String>
where
    S: AsyncRead + Unpin,
{
    let step_deadline = (Instant::now() + step).min(overall);
    match timeout_at(step_deadline, read_frame_bounded_async::<_, StreamCredit>(stream, 4096)).await {
        Ok(Ok(Some(c))) => Ok(c.granted_chunks),
        Ok(Ok(None)) => Err("consumer closed stream before granting next credit window".into()),
        Ok(Err(e)) => Err(format!("stream credit read error: {e}")),
        Err(_) => Err("slow consumer credit deadline exceeded".into()),
    }
}

async fn read_frame_with_budget<S, T>(stream: &mut S, step: Duration, overall: Instant) -> Res<T>
where
    S: AsyncRead + Unpin,
    T: for<'de> Deserialize<'de>,
{
    let step_deadline = (Instant::now() + step).min(overall);
    match timeout_at(step_deadline, read_frame_bounded_async(stream, MAX_STREAM_WIRE_FRAME_BYTES)).await {
        Ok(Ok(Some(v))) => Ok(v),
        Ok(Ok(None)) => Err(E::Refused("peer closed stream before completion".into())),
        Ok(Err(e)) => Err(E::Io(e)),
        Err(_) => Err(E::Refused("stream read deadline exceeded".into())),
    }
}

async fn abort_stream<S>(stream: &mut S, reason: &str, sent_chunks: u64, sent_bytes: u64) -> StreamServerOutcome
where
    S: AsyncWrite + Unpin,
{
    let cancel = StreamFrame::Cancel { reason: reason.to_owned() };
    let _ = tokio::time::timeout(
        Duration::from_millis(50),
        write_frame_bounded_async(stream, &cancel, MAX_STREAM_WIRE_FRAME_BYTES),
    )
    .await;
    StreamServerOutcome { sent_chunks, sent_bytes, cancelled: true, cancel_reason: Some(reason.to_owned()) }
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}
