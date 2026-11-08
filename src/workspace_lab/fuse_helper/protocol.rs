//! Length-prefixed JSON control protocol for the independent FUSE helper.
//!
//! Every frame is `u32` big-endian length (1 byte ..= 16 KiB) followed by one
//! JSON object with `deny_unknown_fields` on the object and on every payload.
//! The parent and the child both refuse an oversized frame, a different
//! `protocol` version and a payload that carries an unexpected field, so an
//! inherited socket cannot be used to smuggle extra commands or paths.
//!
//! The `op`/`args` split keeps the discriminated body explicit: the frame
//! envelope is decoded first, then exactly one payload struct is decoded from
//! `args`. That avoids serde's internally-tagged flattening (which cannot
//! combine with `deny_unknown_fields`) and makes an unknown `op` an error
//! instead of a silently ignored frame.
//!
//! `generation` is a per-spawn nonce: the child adopts the nonce from the first
//! `hello` frame and rejects every later frame that does not carry it, so a
//! stale or duplicated control channel cannot address a helper twice.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    io::{self, Read, Write},
    time::Duration,
};
use uuid::Uuid;

/// Wire version. A mismatch is a protocol error in both directions.
pub const PROTOCOL_VERSION: u32 = 1;
/// Hard cap on one JSON frame, excluding the four length bytes.
pub const MAX_FRAME_BYTES: usize = 16 * 1024;
/// Parent heartbeat period on its own socket (never the control socket).
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_millis(250);
/// Child watchdog deadline: no heartbeat for this long fences everything.
pub const HEARTBEAT_DEADLINE: Duration = Duration::from_millis(1500);
/// Bounded number of unanswered control requests per helper client.
pub const MAX_INFLIGHT: usize = 64;
/// Default deadline for one control request that does not outlive the caller.
pub const REQUEST_DEADLINE: Duration = Duration::from_secs(5);
/// Parent deadline for creating one mount in the child.
pub const MOUNT_DEADLINE: Duration = Duration::from_secs(15);
/// Parent deadline for a freeze acknowledgement (the child drains mutations).
pub const FREEZE_DEADLINE: Duration = Duration::from_secs(30);
/// Parent deadline for the child-side blocking prewarm job.
pub const PREWARM_DEADLINE: Duration = Duration::from_secs(60);
/// Deadline for the out-of-band cancel frame. A cancel that cannot be sent in
/// this window is covered by the child-side operation deadline instead.
pub const ABORT_DEADLINE: Duration = Duration::from_secs(2);
/// Child-side, queue-inclusive mount deadline. It is strictly below the
/// parent's own mount deadline with margin: a mount that outlives this window
/// is replied as failed and can never publish as healthy. A lost reply is still
/// covered by the parent's `AbortMount`; a cancellation that cannot be queued
/// fail-stops the parent generation instead of trusting a best-effort abort.
pub const MOUNT_OP_DEADLINE: Duration = Duration::from_secs(10);
/// Child-side freeze deadline: a freeze whose caller vanished (or whose begin
/// reply was lost) fences itself instead of holding the gate forever.
pub const FREEZE_OP_DEADLINE: Duration = Duration::from_secs(35);

/// One control frame.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Frame {
    pub protocol: u32,
    pub generation: u64,
    pub request_id: u64,
    #[serde(default)]
    pub workspace: Option<Uuid>,
    #[serde(default)]
    pub db_epoch: i64,
    pub op: String,
    #[serde(default)]
    pub args: Value,
}

impl Frame {
    /// Build a frame that carries `body`.
    pub fn request(
        generation: u64,
        request_id: u64,
        workspace: Option<Uuid>,
        db_epoch: i64,
        body: &Body,
    ) -> io::Result<Self> {
        Ok(Self {
            protocol: PROTOCOL_VERSION,
            generation,
            request_id,
            workspace,
            db_epoch,
            op: body.op().to_owned(),
            args: body.args()?,
        })
    }

    /// Decode the discriminated body.
    pub fn body(&self) -> io::Result<Body> {
        Body::decode(&self.op, self.args.clone())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hello {
    pub pid: u32,
    pub version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Heartbeat {
    pub seq: u64,
}

/// Parent-sent mount request. Only the storage root and the workspace UUID
/// cross the process boundary; the child composes every other path from fixed
/// relative subdirectories, so there is no "open this path" command.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MountRequest {
    pub root: String,
    pub workspace: Uuid,
    pub lease_until: i64,
    pub lazy: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Handoff {
    pub epoch: i64,
    pub until: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observe {
    pub epoch: i64,
    pub until: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FenceIfUnchanged {
    pub epoch: i64,
    pub generation: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FreezeBegin {
    pub op_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FreezeFinish {
    pub op_id: u64,
    pub epoch: i64,
    /// `true` only for a proven pre-COMMIT rollback. Everything else fences.
    pub thaw: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AbortFreeze {
    pub op_id: u64,
}

/// Cancel a `mount` whose reply the parent gave up on. `request` names the
/// `request_id` of that mount frame, so a cancel cannot target another mount.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AbortMount {
    pub request: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Prewarm {
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OkReply {
    #[serde(default)]
    pub op_id: Option<u64>,
}

/// Gate state returned by marker/observe/fence queries. `outcome` names the
/// `LeaseObservation` for `observe`; `applied` answers `fence_if_unchanged`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateReply {
    pub epoch: i64,
    pub generation: u64,
    pub phase: String,
    pub writable_until: i64,
    #[serde(default)]
    pub outcome: Option<String>,
    #[serde(default)]
    pub applied: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MountedReply {
    pub epoch: i64,
    pub queue_capacity: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrewarmReply {
    pub files: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorReply {
    pub code: i32,
    pub message: String,
}

/// Discriminated control body.
#[derive(Debug, Clone)]
pub enum Body {
    Hello(Hello),
    Heartbeat(Heartbeat),
    Mount(MountRequest),
    Handoff(Handoff),
    Marker,
    Observe(Observe),
    FenceIfUnchanged(FenceIfUnchanged),
    FreezeBegin(FreezeBegin),
    FreezeFinish(FreezeFinish),
    AbortFreeze(AbortFreeze),
    AbortMount(AbortMount),
    Prewarm(Prewarm),
    Unmount,
    Shutdown,
    Ok(OkReply),
    State(StateReply),
    Mounted(MountedReply),
    Prewarmed(PrewarmReply),
    Unmounted,
    ShuttingDown,
    Error(ErrorReply),
}

fn decode_args<T: serde::de::DeserializeOwned>(op: &str, args: Value) -> io::Result<T> {
    serde_json::from_value(args)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, format!("invalid helper frame `{op}`: {error}")))
}

impl Body {
    pub fn op(&self) -> &'static str {
        match self {
            Body::Hello(_) => "hello",
            Body::Heartbeat(_) => "heartbeat",
            Body::Mount(_) => "mount",
            Body::Handoff(_) => "handoff",
            Body::Marker => "marker",
            Body::Observe(_) => "observe",
            Body::FenceIfUnchanged(_) => "fence_if_unchanged",
            Body::FreezeBegin(_) => "freeze_begin",
            Body::FreezeFinish(_) => "freeze_finish",
            Body::AbortFreeze(_) => "abort_freeze",
            Body::AbortMount(_) => "abort_mount",
            Body::Prewarm(_) => "prewarm",
            Body::Unmount => "unmount",
            Body::Shutdown => "shutdown",
            Body::Ok(_) => "ok",
            Body::State(_) => "state",
            Body::Mounted(_) => "mounted",
            Body::Prewarmed(_) => "prewarmed",
            Body::Unmounted => "unmounted",
            Body::ShuttingDown => "shutting_down",
            Body::Error(_) => "error",
        }
    }

    pub fn args(&self) -> io::Result<Value> {
        Ok(match self {
            Body::Marker | Body::Unmount | Body::Shutdown | Body::Unmounted | Body::ShuttingDown => Value::Null,
            Body::Hello(v) => encode(v)?,
            Body::Heartbeat(v) => encode(v)?,
            Body::Mount(v) => encode(v)?,
            Body::Handoff(v) => encode(v)?,
            Body::Observe(v) => encode(v)?,
            Body::FenceIfUnchanged(v) => encode(v)?,
            Body::FreezeBegin(v) => encode(v)?,
            Body::FreezeFinish(v) => encode(v)?,
            Body::AbortFreeze(v) => encode(v)?,
            Body::AbortMount(v) => encode(v)?,
            Body::Prewarm(v) => encode(v)?,
            Body::Ok(v) => encode(v)?,
            Body::State(v) => encode(v)?,
            Body::Mounted(v) => encode(v)?,
            Body::Prewarmed(v) => encode(v)?,
            Body::Error(v) => encode(v)?,
        })
    }

    pub fn decode(op: &str, args: Value) -> io::Result<Self> {
        Ok(match op {
            "hello" => Body::Hello(decode_args(op, args)?),
            "heartbeat" => Body::Heartbeat(decode_args(op, args)?),
            "mount" => Body::Mount(decode_args(op, args)?),
            "handoff" => Body::Handoff(decode_args(op, args)?),
            "marker" => Body::Marker,
            "observe" => Body::Observe(decode_args(op, args)?),
            "fence_if_unchanged" => Body::FenceIfUnchanged(decode_args(op, args)?),
            "freeze_begin" => Body::FreezeBegin(decode_args(op, args)?),
            "freeze_finish" => Body::FreezeFinish(decode_args(op, args)?),
            "abort_freeze" => Body::AbortFreeze(decode_args(op, args)?),
            "abort_mount" => Body::AbortMount(decode_args(op, args)?),
            "prewarm" => Body::Prewarm(decode_args(op, args)?),
            "unmount" => Body::Unmount,
            "shutdown" => Body::Shutdown,
            "ok" => Body::Ok(decode_args(op, args)?),
            "state" => Body::State(decode_args(op, args)?),
            "mounted" => Body::Mounted(decode_args(op, args)?),
            "prewarmed" => Body::Prewarmed(decode_args(op, args)?),
            "unmounted" => Body::Unmounted,
            "shutting_down" => Body::ShuttingDown,
            "error" => Body::Error(decode_args(op, args)?),
            other => {
                return Err(io::Error::new(io::ErrorKind::InvalidData, format!("unknown helper operation `{other}`")));
            }
        })
    }
}

/// Encode one payload struct as a JSON object.
fn encode<T: Serialize>(value: &T) -> io::Result<Value> {
    serde_json::to_value(value).map_err(io::Error::other)
}

/// Serialize one frame including its length prefix.
pub fn encode_frame(frame: &Frame) -> io::Result<Vec<u8>> {
    let raw = serde_json::to_vec(frame).map_err(io::Error::other)?;
    if raw.is_empty() || raw.len() > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("helper frame is {} bytes, limit is {MAX_FRAME_BYTES}", raw.len()),
        ));
    }
    let mut out = Vec::with_capacity(raw.len() + 4);
    out.extend_from_slice(&(raw.len() as u32).to_be_bytes());
    out.extend_from_slice(&raw);
    Ok(out)
}

/// Write exactly one framed body and flush it.
pub fn write_frame(writer: &mut impl Write, frame: &Frame) -> io::Result<()> {
    let bytes = encode_frame(frame)?;
    writer.write_all(&bytes)?;
    writer.flush()
}

/// Read exactly one frame. Oversized, empty, truncated, non-JSON, unknown-field
/// and mismatched-version frames are hard protocol errors.
pub fn read_frame(reader: &mut impl Read) -> io::Result<Frame> {
    let mut prefix = [0u8; 4];
    reader.read_exact(&mut prefix)?;
    let len = u32::from_be_bytes(prefix) as usize;
    if len == 0 || len > MAX_FRAME_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid helper frame length"));
    }
    let mut raw = vec![0u8; len];
    reader.read_exact(&mut raw)?;
    let frame: Frame = serde_json::from_slice(&raw)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, format!("invalid helper frame: {error}")))?;
    if frame.protocol != PROTOCOL_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("helper protocol {} is not {}", frame.protocol, PROTOCOL_VERSION),
        ));
    }
    Ok(frame)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(body: Body) -> Body {
        let frame = Frame::request(7, 3, Some(Uuid::nil()), 11, &body).unwrap();
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &frame).unwrap();
        let decoded = read_frame(&mut bytes.as_slice()).unwrap();
        assert_eq!(decoded.generation, 7);
        assert_eq!(decoded.request_id, 3);
        assert_eq!(decoded.db_epoch, 11);
        decoded.body().unwrap()
    }

    #[test]
    fn frames_roundtrip_and_keep_the_nonce() {
        let body = roundtrip(Body::FreezeFinish(FreezeFinish { op_id: 9, epoch: 4, thaw: false }));
        match body {
            Body::FreezeFinish(v) => {
                assert_eq!((v.op_id, v.epoch, v.thaw), (9, 4, false));
            }
            other => panic!("unexpected body {other:?}"),
        }
        assert!(matches!(roundtrip(Body::Observe(Observe { epoch: 2, until: 30 })), Body::Observe(_)));
        assert!(matches!(roundtrip(Body::Unmount), Body::Unmount));
    }

    #[test]
    fn unknown_operation_and_extra_fields_are_rejected() {
        let error = Body::decode("exec", Value::Null).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        let extra = serde_json::json!({"epoch": 1, "until": 2, "path": "/etc/shadow"});
        let error = Body::decode("observe", extra).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn control_work_deadlines_are_bounded() {
        // One unanswered-request cap and deadlines that cannot outlive the
        // caller's own operation window.
        assert_eq!(MAX_INFLIGHT, 64);
        assert!(REQUEST_DEADLINE <= Duration::from_secs(30));
        assert!(
            MOUNT_OP_DEADLINE + Duration::from_secs(2) <= MOUNT_DEADLINE,
            "the child-side mount deadline must leave the parent margin to cancel a lost reply"
        );
        assert!(FREEZE_DEADLINE < FREEZE_OP_DEADLINE);
        assert!(HEARTBEAT_INTERVAL * 6 <= HEARTBEAT_DEADLINE);
    }

    #[test]
    fn abort_frames_carry_the_operation_they_cancel() {
        assert!(matches!(
            roundtrip(Body::AbortFreeze(AbortFreeze { op_id: 4 })),
            Body::AbortFreeze(AbortFreeze { op_id: 4 })
        ));
        assert!(matches!(
            roundtrip(Body::AbortMount(AbortMount { request: 9 })),
            Body::AbortMount(AbortMount { request: 9 })
        ));
    }

    #[test]
    fn oversized_and_mismatched_frames_are_rejected() {
        let padded = serde_json::json!({"protocol": PROTOCOL_VERSION, "generation": 1, "request_id": 1,
            "op": "hello", "args": {"pid": 1, "version": 1}, "padding": "x".repeat(MAX_FRAME_BYTES)});
        let raw = serde_json::to_vec(&padded).unwrap();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(raw.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&raw);
        assert!(read_frame(&mut bytes.as_slice()).is_err());
        let mut zero = Vec::new();
        zero.extend_from_slice(&0u32.to_be_bytes());
        assert!(read_frame(&mut zero.as_slice()).is_err());

        let mut stale = Frame::request(1, 1, None, 0, &Body::Unmount).unwrap();
        stale.protocol = PROTOCOL_VERSION + 1;
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &stale).unwrap();
        assert!(read_frame(&mut bytes.as_slice()).is_err());
    }
}
