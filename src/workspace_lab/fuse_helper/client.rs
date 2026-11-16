//! Parent side of the independent FUSE helper: spawn, framing, dispatch, shutdown.
//!
//! The client owns two sockets. The control socket is request/response: a
//! dedicated reader thread resolves bounded per-request channels by
//! `request_id`, and the write mutex is only held for the `write_all` of one
//! frame, never across a wait. The heartbeat socket is written by its own
//! standard thread every [`HEARTBEAT_INTERVAL`], so liveness never depends on
//! Tokio progress or on the control reader.
//! A child crash surfaces as a control EOF: every pending request fails with
//! `ECONNRESET` and `alive()` turns false. Nothing here pretends a crashed
//! child kept serving reads.
use super::protocol::{
    ABORT_DEADLINE, AbortFreeze, AbortMount, Body, ErrorReply, FREEZE_DEADLINE, FenceIfUnchanged, Frame, FreezeBegin,
    FreezeFinish, HEARTBEAT_INTERVAL, Handoff, Heartbeat, Hello, MAX_INFLIGHT, MOUNT_DEADLINE, MountRequest, Observe,
    PREWARM_DEADLINE, PROTOCOL_VERSION, Prewarm, PrewarmReply, REQUEST_DEADLINE, StateReply, encode_frame, read_frame,
    write_frame,
};
use crate::workspace_lab::fuse_mount::FreezeDecision;
use std::{
    collections::HashMap,
    io::{self, Write},
    net::Shutdown,
    os::{
        fd::{AsRawFd, OwnedFd, RawFd},
        unix::{net::UnixStream, process::CommandExt},
    },
    path::Path,
    process::{Command, Stdio},
    sync::{
        Arc, Mutex, MutexGuard, TryLockError,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{self, RecvTimeoutError, TrySendError},
    },
    thread,
    time::{Duration, Instant},
};
use uuid::Uuid;

#[path = "client_child.rs"]
mod child_lifecycle;
use child_lifecycle::{ChildSlot, ExitObservation, ExitView};

/// Bound on queued cancel frames. One worker sends them, so a caller that
/// abandons a begin/mount can never spawn an unbounded number of threads.
const ABORT_QUEUE: usize = 64;
/// How often the reaper checks the dead flag without relying on the channel.
const REAPER_TICK: Duration = Duration::from_millis(50);
/// Bounded poll granularity for control-mutex admission. The absolute call or
/// teardown deadline is re-read on every iteration.
const CONTROL_POLL: Duration = Duration::from_millis(10);
/// Bounded poll granularity for socket writability. The absolute call or
/// teardown deadline is re-read on every iteration.
const WRITE_POLL: Duration = Duration::from_millis(10);

#[cfg(any(target_os = "linux", target_os = "android"))]
const CONTROL_SEND_FLAGS: i32 = libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL;
#[cfg(not(any(target_os = "linux", target_os = "android")))]
const CONTROL_SEND_FLAGS: i32 = libc::MSG_DONTWAIT;

/// Failure while talking to the helper. The code is an errno value when one is
/// meaningful, so callers can distinguish `EBUSY`/`ESTALE`/timeouts.
#[derive(Debug, Clone)]
pub struct HelperError {
    pub code: i32,
    pub message: String,
}

impl HelperError {
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
    }

    pub fn disconnected() -> Self {
        Self::new(libc::ECONNRESET, "workspace FUSE helper is not available")
    }

    pub fn protocol(message: impl Into<String>) -> Self {
        Self::new(libc::EPROTO, message.into())
    }

    pub fn is_disconnected(&self) -> bool {
        self.code == libc::ECONNRESET
    }

    pub fn is_protocol(&self) -> bool {
        self.code == libc::EPROTO
    }
}

impl std::fmt::Display for HelperError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (errno {})", self.message, self.code)
    }
}

impl std::error::Error for HelperError {}

struct PendingReply {
    sender: mpsc::Sender<Result<Body, HelperError>>,
    /// Workspace the request was addressed to; a reply must name it again.
    workspace: Option<Uuid>,
    /// Non-zero when the reply must echo the request epoch.
    db_epoch: i64,
}

/// A cancellation that must still reach the child when the caller is gone.
/// The child also bounds every operation, so a full queue is a lost hint.
enum AbortJob {
    Freeze { workspace: Uuid, epoch: i64, op_id: u64 },
    Mount { workspace: Uuid, request: u64 },
}

enum ReapRequest {
    GenerationDead,
}

struct Inner {
    generation: u64,
    control: Mutex<UnixStream>,
    heartbeat: Mutex<UnixStream>,
    /// Extra clones used to wake a blocked reader/writer with `shutdown(2)`
    /// during fail-closed generation death, without taking those mutexes.
    control_shutdown: UnixStream,
    heartbeat_shutdown: UnixStream,
    pending: Mutex<HashMap<u64, PendingReply>>,
    aborts: mpsc::SyncSender<AbortJob>,
    reaper: mpsc::SyncSender<ReapRequest>,
    next_request: AtomicU64,
    dead: AtomicBool,
    stop: AtomicBool,
    death: Mutex<Option<HelperError>>,
    /// One absolute teardown deadline, once shutdown starts. Every later
    /// shutdown/reap phase may only tighten or reuse it.
    teardown_deadline: Mutex<Option<Instant>>,
    child: Mutex<ChildSlot>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn control_deadline_error() -> HelperError {
    HelperError::new(libc::ETIMEDOUT, "workspace FUSE helper control deadline expired")
}

/// Admit one control writer without blocking past the caller's absolute
/// deadline. The deadline closure re-reads the current teardown cap on every
/// iteration, so a deadline published while this writer waits for the mutex
/// immediately tightens the wait.
fn lock_until<'a, T, F>(mutex: &'a Mutex<T>, mut deadline: F) -> Result<MutexGuard<'a, T>, HelperError>
where
    F: FnMut() -> Instant,
{
    loop {
        let limit = deadline();
        let now = Instant::now();
        if now >= limit {
            return Err(control_deadline_error());
        }
        match mutex.try_lock() {
            Ok(guard) => return Ok(guard),
            Err(TryLockError::Poisoned(poisoned)) => return Ok(poisoned.into_inner()),
            Err(TryLockError::WouldBlock) => {
                thread::sleep(limit.saturating_duration_since(now).min(CONTROL_POLL));
            }
        }
    }
}

/// Wait until the exact control socket is writable or `wait` expires. The
/// duration is deliberately short; the writer re-reads its absolute deadline
/// after every poll instead of treating this as a fresh write grace.
fn poll_writable(fd: RawFd, wait: Duration) -> Result<(), HelperError> {
    let timeout = wait.min(WRITE_POLL).as_millis() as i32;
    let mut pollfd = libc::pollfd { fd, events: libc::POLLOUT, revents: 0 };
    // SAFETY: one valid pollfd is supplied and the timeout is bounded.
    let ready = unsafe { libc::poll(&mut pollfd, 1, timeout) };
    if ready >= 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::EINTR) {
        // Return to the writer so it re-reads the absolute deadline instead of
        // restarting this poll window.
        return Ok(());
    }
    Err(HelperError::new(
        error.raw_os_error().unwrap_or(libc::EIO),
        format!("workspace FUSE helper control poll failed: {error}"),
    ))
}

/// One complete-frame nonblocking send attempt. A short or failed attempt runs
/// `terminal` before this function returns, so a caller that holds the control
/// guard still marks the exact generation dead before releasing that guard.
/// It never retries EINTR/short writes or restarts a grace.
fn send_complete_or_terminal<F, M>(bytes: &[u8], send: F, terminal: M) -> bool
where
    F: FnOnce(*const u8, usize) -> io::Result<usize>,
    M: FnOnce(i32),
{
    match send(bytes.as_ptr(), bytes.len()) {
        Ok(sent) if sent == bytes.len() => true,
        Ok(_) => {
            terminal(libc::EIO);
            false
        }
        Err(error) => {
            terminal(error.raw_os_error().unwrap_or(libc::EIO));
            false
        }
    }
}

/// Write one already-serialized control frame without blocking past the
/// absolute deadline. The deadline closure re-reads the current teardown cap
/// on every send/poll iteration. A partial frame is never followed by another
/// frame: the caller fail-closes the generation on any error.
fn write_bytes_until<F>(stream: &mut UnixStream, mut bytes: &[u8], mut deadline: F) -> Result<(), HelperError>
where
    F: FnMut() -> Instant,
{
    let fd = stream.as_raw_fd();
    while !bytes.is_empty() {
        let limit = deadline();
        let now = Instant::now();
        if now >= limit {
            return Err(control_deadline_error());
        }
        // SAFETY: the socket fd is owned by `stream`; the pointer covers the
        // remaining bytes and `MSG_DONTWAIT` keeps every call nonblocking.
        let sent = unsafe { libc::send(fd, bytes.as_ptr().cast(), bytes.len(), CONTROL_SEND_FLAGS) };
        if sent > 0 {
            bytes = &bytes[sent as usize..];
            continue;
        }
        if sent == 0 {
            return Err(HelperError::new(libc::EPIPE, "workspace FUSE helper control write closed"));
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::EINTR) => {}
            Some(code) if code == libc::EAGAIN || code == libc::EWOULDBLOCK => {
                let remaining = limit.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(control_deadline_error());
                }
                poll_writable(fd, remaining)?;
            }
            _ => {
                return Err(HelperError::new(
                    error.raw_os_error().unwrap_or(libc::EIO),
                    format!("workspace FUSE helper control write failed: {error}"),
                ));
            }
        }
    }
    stream.flush().map_err(|error| {
        HelperError::new(
            error.raw_os_error().unwrap_or(libc::EIO),
            format!("workspace FUSE helper control flush failed: {error}"),
        )
    })
}

impl Inner {
    fn mark_dead(&self) {
        self.fail_generation(libc::ECONNRESET, "workspace FUSE helper is not available");
    }

    /// Fail-close the whole helper generation. This never joins a reader or
    /// waits for the child: it records the first reason, fails every waiter,
    /// stops the heartbeat, wakes blocked socket I/O, and asks the one
    /// dedicated reaper thread to kill and reap the child.
    fn fail_generation(&self, code: i32, message: impl Into<String>) {
        let reason = HelperError::new(code, message);
        if !self.dead.swap(true, Ordering::AcqRel) {
            *lock(&self.death) = Some(reason.clone());
        }
        self.stop.store(true, Ordering::Release);
        // `shutdown` on either duplicate wakes every blocked read/write on the
        // shared socket, including the control reader that must drop its Arc.
        let _ = self.control_shutdown.shutdown(Shutdown::Both);
        let _ = self.heartbeat_shutdown.shutdown(Shutdown::Both);
        let orphaned: Vec<PendingReply> = {
            let mut pending = lock(&self.pending);
            pending.drain().map(|(_, pending)| pending).collect()
        };
        for pending in orphaned {
            let _ = pending.sender.send(Err(reason.clone()));
        }
        let _ = self.reaper.try_send(ReapRequest::GenerationDead);
    }

    fn failure(&self) -> HelperError {
        lock(&self.death).clone().unwrap_or_else(HelperError::disconnected)
    }

    /// Publish the one absolute teardown deadline. Repeated calls only tighten
    /// it, so the RPC wait, child-exit wait, reaper and last-resort drop never
    /// reset a fresh grace after the shared shutdown budget is exhausted.
    fn begin_teardown_deadline(&self, deadline: Instant) -> Instant {
        let mut current = lock(&self.teardown_deadline);
        let effective = match *current {
            Some(existing) => existing.min(deadline),
            None => deadline,
        };
        *current = Some(effective);
        effective
    }

    fn teardown_deadline(&self) -> Option<Instant> {
        *lock(&self.teardown_deadline)
    }

    /// Tighten one call deadline with any already-published teardown cap.
    fn effective_deadline(&self, deadline: Instant) -> Instant {
        self.teardown_deadline().map_or(deadline, |limit| deadline.min(limit))
    }

    fn lock_control_until(&self, deadline: Instant) -> Result<MutexGuard<'_, UnixStream>, HelperError> {
        lock_until(&self.control, || self.effective_deadline(deadline))
    }

    /// Best-effort canonical shutdown frame when no budget remains. It never
    /// waits for the mutex or socket: if it cannot write the whole frame, the
    /// caller fail-closes the generation and the deadline-capped reaper kills
    /// and reaps the exact child. It is not evidence of a clean unmount.
    fn try_send_shutdown_frame(&self) -> bool {
        if self.dead.load(Ordering::Acquire) {
            return false;
        }
        let frame = match Frame::request(self.generation, self.next_request(), None, 0, &Body::Shutdown) {
            Ok(frame) => frame,
            Err(_) => return false,
        };
        let bytes = match encode_frame(&frame) {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };
        let mut control = match self.control.try_lock() {
            Ok(control) => control,
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            Err(TryLockError::WouldBlock) => return false,
        };
        if self.dead.load(Ordering::Acquire) {
            return false;
        }
        let fd = control.as_raw_fd();
        // Exactly one nonblocking attempt: no retry loop and no grace reset.
        // EINTR, EAGAIN, a short write or any other error is an unproved
        // best-effort attempt. Mark the exact generation terminal while this
        // guard is still held so a concurrent shutdown sender that acquires the
        // control mutex afterwards rechecks `dead` and cannot append a frame to
        // a corrupted stream.
        // SAFETY: the socket fd is owned by `control`; the pointer covers the
        // canonical frame bytes and `MSG_DONTWAIT` never blocks.
        if !send_complete_or_terminal(
            &bytes,
            |pointer, length| {
                // Capture the syscall errno immediately on failure, before any
                // intervening call can overwrite it; positive results are the
                // completed byte count.
                let sent = unsafe { libc::send(fd, pointer.cast(), length, CONTROL_SEND_FLAGS) };
                if sent < 0 { Err(io::Error::last_os_error()) } else { Ok(sent as usize) }
            },
            |code| {
                self.fail_generation(code, "workspace FUSE helper shutdown frame was not sent completely");
            },
        ) {
            return false;
        }
        if let Err(error) = control.flush() {
            let code = error.raw_os_error().unwrap_or(libc::EIO);
            self.fail_generation(code, "workspace FUSE helper shutdown flush failed");
            return false;
        }
        true
    }

    fn deliver(&self, frame: Frame) {
        let expected = lock(&self.pending).remove(&frame.request_id);
        let Some(expected) = expected else { return };
        // Bind the reply to the request that is still waiting: another
        // generation, workspace or epoch must not be mistaken for this answer.
        let result = if frame.generation != self.generation {
            Err(HelperError::protocol("helper reply carries another generation"))
        } else if frame.workspace != expected.workspace {
            Err(HelperError::protocol("helper reply does not match the request workspace"))
        } else {
            match frame.body() {
                // Error frames keep the caller's errno even when the child
                // answers with a zero epoch (a fast-failing busy/stale reply).
                // They are decoded before the success-frame epoch check, which
                // stays strict for every non-error body.
                Ok(Body::Error(ErrorReply { code, message })) => Err(HelperError::new(code, message)),
                Ok(_body) if expected.db_epoch != 0 && frame.db_epoch != expected.db_epoch => {
                    Err(HelperError::protocol("helper reply does not match the request epoch"))
                }
                Ok(body) => Ok(body),
                Err(error) => Err(HelperError::protocol(error.to_string())),
            }
        };
        let protocol_failure =
            result.as_ref().err().filter(|error| error.is_protocol()).map(|error| error.message.clone());
        let _ = expected.sender.send(result);
        if let Some(message) = protocol_failure {
            // One malformed/mismatched reply means the generation can no
            // longer be trusted for any healthy operation.
            self.fail_generation(libc::EPROTO, message);
        }
    }

    fn queue_abort(&self, job: AbortJob) {
        // A cancellation may not be silently dropped: if the bounded worker
        // cannot take it, the only fail-closed outcome is to stop the whole
        // generation. This call itself never blocks; the dedicated reaper owns
        // the kill/reap.
        match self.aborts.try_send(job) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => self.fail_generation(
                libc::EIO,
                "workspace FUSE helper cancellation queue is full; fail-stopping generation",
            ),
            Err(TrySendError::Disconnected(_)) => self.fail_generation(
                libc::ECONNRESET,
                "workspace FUSE helper cancellation worker is gone; fail-stopping generation",
            ),
        }
    }

    fn next_request(&self) -> u64 {
        self.next_request.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// Send one request and wait for the matching reply with a deadline.
    ///
    /// The request id is returned even when the wait timed out, so the caller
    /// can send a cancel that names exactly this frame.
    fn call_full(
        &self,
        workspace: Option<Uuid>,
        db_epoch: i64,
        body: Body,
        grace: Duration,
    ) -> (u64, Result<Body, HelperError>) {
        self.call_full_until(workspace, db_epoch, body, Instant::now() + grace)
    }

    /// Send one request and wait for the matching reply without extending the
    /// caller's absolute deadline.
    fn call_full_until(
        &self,
        workspace: Option<Uuid>,
        db_epoch: i64,
        body: Body,
        deadline: Instant,
    ) -> (u64, Result<Body, HelperError>) {
        if self.dead.load(Ordering::Acquire) {
            return (0, Err(self.failure()));
        }
        let deadline = self.effective_deadline(deadline);
        if Instant::now() >= deadline {
            return (0, Err(control_deadline_error()));
        }
        let request_id = self.next_request();
        let (sender, receiver) = mpsc::channel();
        {
            let mut pending = lock(&self.pending);
            if pending.len() >= MAX_INFLIGHT {
                return (
                    request_id,
                    Err(HelperError::new(libc::EBUSY, "too many unanswered workspace FUSE helper requests")),
                );
            }
            pending.insert(request_id, PendingReply { sender, workspace, db_epoch });
        }
        let frame = match Frame::request(self.generation, request_id, workspace, db_epoch, &body) {
            Ok(frame) => frame,
            Err(error) => {
                lock(&self.pending).remove(&request_id);
                return (request_id, Err(HelperError::protocol(error.to_string())));
            }
        };
        let bytes = match encode_frame(&frame) {
            Ok(bytes) => bytes,
            Err(error) => {
                lock(&self.pending).remove(&request_id);
                return (request_id, Err(HelperError::protocol(error.to_string())));
            }
        };
        let mut control = match self.lock_control_until(deadline) {
            Ok(control) => control,
            Err(error) => {
                lock(&self.pending).remove(&request_id);
                return (request_id, Err(error));
            }
        };
        if self.dead.load(Ordering::Acquire) {
            lock(&self.pending).remove(&request_id);
            return (request_id, Err(self.failure()));
        }
        // A teardown deadline may have been published while this caller waited
        // for the control mutex. Re-read it immediately before touching the
        // stream so the write itself consumes the tightened absolute budget.
        let deadline = self.effective_deadline(deadline);
        if Instant::now() >= deadline {
            lock(&self.pending).remove(&request_id);
            return (request_id, Err(control_deadline_error()));
        }
        // Only the write of this frame is under the mutex; the reply is
        // awaited with the lock released so one slow operation cannot
        // serialize every other mount's control traffic. A partial write is
        // fail-closed here and never reused as another frame.
        if let Err(error) = write_bytes_until(&mut control, &bytes, || self.effective_deadline(deadline)) {
            lock(&self.pending).remove(&request_id);
            self.fail_generation(error.code, error.message.clone());
            return (request_id, Err(error));
        }
        let remaining = self.effective_deadline(deadline).saturating_duration_since(Instant::now());
        match receiver.recv_timeout(remaining) {
            Ok(result) => (request_id, result),
            Err(RecvTimeoutError::Timeout) => {
                lock(&self.pending).remove(&request_id);
                (request_id, Err(HelperError::new(libc::ETIMEDOUT, "workspace FUSE helper request deadline expired")))
            }
            Err(RecvTimeoutError::Disconnected) => (request_id, Err(self.failure())),
        }
    }

    fn call(
        &self,
        workspace: Option<Uuid>,
        db_epoch: i64,
        body: Body,
        deadline: Duration,
    ) -> Result<Body, HelperError> {
        self.call_full(workspace, db_epoch, body, deadline).1
    }

    fn call_until(
        &self,
        workspace: Option<Uuid>,
        db_epoch: i64,
        body: Body,
        deadline: Instant,
    ) -> Result<Body, HelperError> {
        self.call_full_until(workspace, db_epoch, body, deadline).1
    }

    fn wait_exit_until(&self, deadline: Instant) -> Result<(), HelperError> {
        loop {
            // One short observation under the lock; sleep never happens here.
            let observation = {
                let mut slot = lock(&self.child);
                slot.observe()
            };
            match observation {
                ExitObservation::Exited(Ok(status)) if status.success => return Ok(()),
                ExitObservation::Exited(Ok(status)) => {
                    return Err(HelperError::new(
                        libc::ECHILD,
                        format!("workspace FUSE helper exited with {}", status.description),
                    ));
                }
                ExitObservation::Exited(Err(error)) => return Err(HelperError::new(libc::ECHILD, error)),
                ExitObservation::Missing => {
                    return Err(HelperError::new(
                        libc::ECHILD,
                        "workspace FUSE helper child handle disappeared before an exit was observed",
                    ));
                }
                ExitObservation::Running | ExitObservation::Reaping => {
                    let now = Instant::now();
                    if now >= deadline {
                        return Err(HelperError::new(
                            libc::ETIMEDOUT,
                            "workspace FUSE helper did not exit within the shutdown deadline",
                        ));
                    }
                    thread::sleep(deadline.saturating_duration_since(now).min(Duration::from_millis(10)));
                }
            }
        }
    }

    /// The one fixed reaper keeps polling until `Child::try_wait` reports a
    /// real exit. A SIGKILLed process stuck in D-state is not dropped
    /// unreaped. When shutdown published an absolute deadline, the reaper
    /// stops waiting at that same deadline and records a failure instead of
    /// starting a fresh grace. Without a shutdown deadline (for example a
    /// crash-triggered generation death), this dedicated thread may outlive a
    /// bounded caller as before.
    fn reap_child_until_exit(&self) {
        let child = {
            let mut slot = lock(&self.child);
            slot.take_for_reap()
        };
        let Some(mut child) = child else { return };
        let _ = child.kill();
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    lock(&self.child).record_exit(Ok(ExitView::from(status)));
                    return;
                }
                Ok(None) => {
                    let now = Instant::now();
                    let Some(limit) = self.teardown_deadline() else {
                        thread::sleep(Duration::from_millis(10));
                        continue;
                    };
                    if now >= limit {
                        lock(&self.child).record_exit(Err(
                            "workspace FUSE helper was killed but did not reap within the shutdown deadline".into(),
                        ));
                        std::mem::forget(child);
                        return;
                    }
                    thread::sleep(limit.saturating_duration_since(now).min(Duration::from_millis(10)));
                }
                Err(error) => {
                    lock(&self.child).record_exit(Err(error.to_string()));
                    return;
                }
            }
        }
    }

    /// Last-resort teardown when the last `Arc` is gone and no reaper can own
    /// the handle. Bounded; if the child still has not exited, forget the
    /// handle instead of dropping an unreaped `Child`. A published shutdown
    /// deadline is a hard cap, so Drop never starts a fresh grace after the
    /// shared budget is exhausted.
    fn reap_for_drop(&self, grace: Duration) {
        let child = {
            let mut slot = lock(&self.child);
            slot.take_for_reap()
        };
        let Some(mut child) = child else { return };
        let _ = child.kill();
        let proposed = Instant::now() + grace;
        let deadline = self.teardown_deadline().map_or(proposed, |limit| limit.min(proposed));
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    lock(&self.child).record_exit(Ok(ExitView::from(status)));
                    return;
                }
                Ok(None) => {
                    let now = Instant::now();
                    if now >= deadline {
                        lock(&self.child).record_exit(Err(
                            "workspace FUSE helper was killed but did not reap within the shutdown deadline".into(),
                        ));
                        std::mem::forget(child);
                        return;
                    }
                    thread::sleep(deadline.saturating_duration_since(now).min(Duration::from_millis(10)));
                }
                Err(error) => {
                    lock(&self.child).record_exit(Err(error.to_string()));
                    return;
                }
            }
        }
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        // No other thread can own this `Arc` here, so locks are uncontended.
        // Stop and reap without joining: a thread handle cycle or blocked
        // reader must never keep the generation alive.
        self.stop.store(true, Ordering::Release);
        self.dead.store(true, Ordering::Release);
        let _ = self.control_shutdown.shutdown(Shutdown::Both);
        let _ = self.heartbeat_shutdown.shutdown(Shutdown::Both);
        let _ = self.reaper.try_send(ReapRequest::GenerationDead);
        self.reap_for_drop(Duration::from_secs(1));
    }
}

/// One helper child and the parent-side view of it.
#[derive(Clone)]
pub struct HelperClient {
    inner: Arc<Inner>,
}

impl HelperClient {
    /// Spawn the helper child and complete the `hello` handshake.
    ///
    /// The child is placed in its own process group so a harness `killpg` of the
    /// API process group does not also kill a helper that is still serving
    /// blocking FUSE requests; it learns about parent loss from the heartbeat
    /// deadline instead.
    pub fn spawn() -> io::Result<Self> {
        let exe = std::env::current_exe()?;
        let (parent_control, child_control) = UnixStream::pair()?;
        let (parent_heartbeat, child_heartbeat) = UnixStream::pair()?;
        let mut command = Command::new(exe);
        command.arg(super::HELPER_ARG);
        command.env_clear();
        for (name, value) in super::helper_env(|name| std::env::var_os(name)) {
            command.env(name, value);
        }
        command.stdin(Stdio::from(OwnedFd::from(child_control)));
        command.stdout(Stdio::from(OwnedFd::from(child_heartbeat)));
        command.stderr(Stdio::inherit());
        command.process_group(0);
        let child = command.spawn()?;

        let generation = Uuid::new_v4().as_u64_pair().0.max(1);
        let mut control = parent_control;
        let hello = Frame::request(
            generation,
            1,
            None,
            0,
            &Body::Hello(Hello { pid: std::process::id(), version: PROTOCOL_VERSION }),
        )
        .map_err(io::Error::other)?;
        let mut child = child;
        let handshake = write_frame(&mut control, &hello).and_then(|()| read_frame(&mut control)).and_then(|frame| {
            match frame.body() {
                Ok(Body::Ok(_)) if frame.generation == generation => Ok(()),
                Ok(Body::Error(ErrorReply { code, message })) => {
                    Err(io::Error::other(format!("helper refused handshake: {message} (errno {code})")))
                }
                Ok(_) => Err(io::Error::new(io::ErrorKind::InvalidData, "helper handshake reply is not an ack")),
                Err(error) => Err(error),
            }
        });
        if let Err(error) = handshake {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }

        let reader_stream = control.try_clone()?;
        let heartbeat_stream = parent_heartbeat;
        let control_shutdown = control.try_clone()?;
        let heartbeat_shutdown = heartbeat_stream.try_clone()?;
        let (aborts, abort_jobs) = mpsc::sync_channel(ABORT_QUEUE);
        let (reaper, reap_jobs) = mpsc::sync_channel(1);
        let inner = Arc::new(Inner {
            generation,
            control: Mutex::new(control),
            heartbeat: Mutex::new(heartbeat_stream),
            control_shutdown,
            heartbeat_shutdown,
            pending: Mutex::new(HashMap::new()),
            aborts,
            reaper,
            next_request: AtomicU64::new(1),
            dead: AtomicBool::new(false),
            stop: AtomicBool::new(false),
            death: Mutex::new(None),
            teardown_deadline: Mutex::new(None),
            child: Mutex::new(ChildSlot::running(child)),
        });

        let reader_inner = inner.clone();
        thread::Builder::new()
            .name("fuse-helper-control-reader".into())
            .spawn(move || control_reader(reader_inner, reader_stream))?;
        let heartbeat_inner = inner.clone();
        thread::Builder::new().name("fuse-helper-heartbeat".into()).spawn(move || heartbeat_writer(heartbeat_inner))?;
        let abort_inner = inner.clone();
        thread::Builder::new()
            .name("fuse-helper-freeze-abort".into())
            .spawn(move || abort_worker(abort_inner, abort_jobs))?;
        // Exactly one dedicated reaper; its handle is detached so `Inner`
        // never owns a join handle whose closure owns another `Inner` Arc.
        let reap_inner = inner.clone();
        thread::Builder::new().name("fuse-helper-reaper".into()).spawn(move || reap_child(reap_inner, reap_jobs))?;
        Ok(Self { inner })
    }

    pub fn generation(&self) -> u64 {
        self.inner.generation
    }

    /// False after control EOF, a failed write or a completed shutdown.
    pub fn alive(&self) -> bool {
        !self.inner.dead.load(Ordering::Acquire)
    }

    /// True only after the exact helper child was actually reaped. A dead
    /// control generation with a still-running or unreaped child is not
    /// quiescent and remains shutdown-visible.
    pub fn child_reaped(&self) -> bool {
        lock(&self.inner.child).reaped()
    }

    /// Publish the one absolute helper teardown deadline before scheduling the
    /// blocking shutdown. This also caps a last-`Arc` drop/reaper that runs
    /// before the blocking closure is dispatched, so it cannot start a fresh
    /// grace after the shared shutdown budget is exhausted.
    pub fn publish_teardown_deadline(&self, deadline: Instant) -> Instant {
        self.inner.begin_teardown_deadline(deadline)
    }

    /// Send one request and wait for the matching reply with a deadline.
    pub fn call(
        &self,
        workspace: Option<Uuid>,
        db_epoch: i64,
        body: Body,
        deadline: Duration,
    ) -> Result<Body, HelperError> {
        self.inner.call(workspace, db_epoch, body, deadline)
    }

    /// Mount one workspace. Only the storage root and the UUID are sent.
    pub fn mount(
        &self,
        root: &Path,
        workspace: Uuid,
        db_epoch: i64,
        lease_until: i64,
        lazy: bool,
    ) -> Result<(), HelperError> {
        let root =
            root.to_str().ok_or_else(|| HelperError::new(libc::EINVAL, "storage root is not valid UTF-8"))?.to_owned();
        let (request_id, reply) = self.inner.call_full(
            Some(workspace),
            db_epoch,
            Body::Mount(MountRequest { root, workspace, lease_until, lazy }),
            MOUNT_DEADLINE,
        );
        let failed = match reply {
            Ok(Body::Mounted(_)) => return Ok(()),
            Ok(other) => HelperError::protocol(format!("unexpected mount reply `{}`", other.op())),
            Err(error) => error,
        };
        // The reply is not proof the child stopped working: on a timeout or a
        // malformed answer, cancel the exact mount frame so a late child-side
        // completion is torn down instead of staying writable without an owner.
        if request_id != 0 && matches!(failed.code, libc::ETIMEDOUT | libc::EPROTO) {
            // Queue the exact-frame cancel for the normal path, then also
            // conservatively fail-stop the generation: a bounded worker may
            // still be behind other cancellations, and a mount that published
            // before the child deadline could otherwise stay writable without
            // an owner. The child is killed/reaped by the dedicated reaper.
            self.inner.queue_abort(AbortJob::Mount { workspace, request: request_id });
            self.inner.fail_generation(
                failed.code,
                format!("mount did not produce a trustworthy reply; fail-stopping generation: {}", failed.message),
            );
        }
        Err(failed)
    }

    pub fn handoff(&self, workspace: Uuid, epoch: i64, until: i64) -> Result<(), HelperError> {
        let reply = self.call(Some(workspace), epoch, Body::Handoff(Handoff { epoch, until }), REQUEST_DEADLINE)?;
        match reply {
            Body::Ok(_) => Ok(()),
            other => Err(HelperError::protocol(format!("unexpected handoff reply `{}`", other.op()))),
        }
    }

    pub fn marker(&self, workspace: Uuid) -> Result<StateReply, HelperError> {
        state_reply(self.call(Some(workspace), 0, Body::Marker, REQUEST_DEADLINE)?)
    }

    /// Ordered lease observation; a stale query cannot re-authorize a newer epoch.
    pub fn observe(&self, workspace: Uuid, epoch: i64, until: i64) -> Result<StateReply, HelperError> {
        state_reply(self.call(Some(workspace), epoch, Body::Observe(Observe { epoch, until }), REQUEST_DEADLINE)?)
    }

    /// Conditional fence for a missing lease row.
    pub fn fence_if_unchanged(&self, workspace: Uuid, epoch: i64, generation: u64) -> Result<bool, HelperError> {
        let reply = self.call(
            Some(workspace),
            epoch,
            Body::FenceIfUnchanged(FenceIfUnchanged { epoch, generation }),
            REQUEST_DEADLINE,
        )?;
        Ok(state_reply(reply)?.applied.unwrap_or(false))
    }

    /// Register a freeze attempt before the begin frame is written.
    ///
    /// The operation id exists before the RPC, so a timeout, a cancelled async
    /// task or a panic always has a cancel to send. The returned attempt is
    /// RAII: dropping it without [`FreezeAttempt::begin`] success aborts the op.
    pub fn freeze_attempt(&self, workspace: Uuid, epoch: i64) -> FreezeAttempt {
        FreezeAttempt { client: self.clone(), workspace, epoch, op_id: self.inner.next_request(), armed: true }
    }

    /// Run the child-side blocking prewarm job.
    pub fn prewarm(&self, workspace: Uuid, paths: Vec<String>) -> Result<(u64, u64), HelperError> {
        let reply = self.call(Some(workspace), 0, Body::Prewarm(Prewarm { paths }), PREWARM_DEADLINE)?;
        match reply {
            Body::Prewarmed(PrewarmReply { files, bytes }) => Ok((files, bytes)),
            other => Err(HelperError::protocol(format!("unexpected prewarm reply `{}`", other.op()))),
        }
    }

    pub fn unmount(&self, workspace: Uuid) -> Result<(), HelperError> {
        let failed = match self.call(Some(workspace), 0, Body::Unmount, MOUNT_DEADLINE) {
            Ok(Body::Unmounted) => return Ok(()),
            Ok(other) => HelperError::protocol(format!("unexpected unmount reply `{}`", other.op())),
            Err(error) => error,
        };
        // A timed-out (or malformed) unmount reply is not proof the child
        // stopped working: the teardown may still be running, or the mount may
        // still be owned, and the API must not keep claiming a healthy helper
        // after a blocked cleanup. Fail-close the generation exactly like a
        // mount timeout; the dedicated reaper kills and reaps that child, and
        // the next mount builds a fresh generation instead of reusing it.
        if matches!(failed.code, libc::ETIMEDOUT | libc::EPROTO) {
            self.inner.fail_generation(
                failed.code,
                format!("unmount did not produce a trustworthy reply; fail-stopping generation: {}", failed.message),
            );
        }
        Err(failed)
    }

    /// Ask the child to fence, unmount and exit, then reap it within `grace`.
    ///
    /// A helper that does not exit is killed and reported as an error: shutdown
    /// either observes a real exit or fails, it never claims success. The
    /// grace is converted once to an absolute deadline shared by the RPC and
    /// the exit wait; the old caller-visible method is preserved.
    pub fn shutdown(&self, grace: Duration) -> Result<(), HelperError> {
        self.shutdown_until(Instant::now() + grace)
    }

    /// Deadline-aware shutdown used by the normal signal path. The RPC wait,
    /// child-exit wait, reaper and last-resort drop all consume the same
    /// absolute deadline and may only tighten it. No fresh grace is started
    /// after the caller's remaining normal-shutdown budget is exhausted.
    pub fn shutdown_until(&self, deadline: Instant) -> Result<(), HelperError> {
        let deadline = self.inner.begin_teardown_deadline(deadline);
        if Instant::now() >= deadline {
            // No remaining budget: still make one nonblocking, canonical
            // shutdown/fence attempt, then fail-closed the exact generation so
            // the deadline-capped reaper performs the owned kill/reap. This
            // path never reports success without an observed child exit.
            let attempted = self.inner.try_send_shutdown_frame();
            self.inner.stop.store(true, Ordering::Release);
            return match self.inner.wait_exit_until(deadline) {
                Ok(()) => {
                    self.inner.mark_dead();
                    Ok(())
                }
                Err(error) => {
                    self.inner.fail_generation(error.code, error.message.clone());
                    if attempted { Err(error) } else { Err(control_deadline_error()) }
                }
            };
        }
        let request_deadline = deadline.min(Instant::now() + REQUEST_DEADLINE);
        let request = self.inner.call_until(None, 0, Body::Shutdown, request_deadline);
        self.inner.stop.store(true, Ordering::Release);
        match self.inner.wait_exit_until(deadline) {
            Ok(()) => {
                self.inner.mark_dead();
                match request {
                    Ok(Body::ShuttingDown) | Err(HelperError { code: libc::ECONNRESET, .. }) => Ok(()),
                    Ok(other) => Err(HelperError::protocol(format!("unexpected shutdown reply `{}`", other.op()))),
                    Err(error) => Err(error),
                }
            }
            Err(error) => {
                self.inner.fail_generation(error.code, error.message.clone());
                Err(error)
            }
        }
    }
}

fn state_reply(body: Body) -> Result<StateReply, HelperError> {
    match body {
        Body::State(state) => Ok(state),
        other => Err(HelperError::protocol(format!("unexpected reply `{}`", other.op()))),
    }
}

fn control_reader(inner: Arc<Inner>, mut stream: UnixStream) {
    loop {
        match read_frame(&mut stream) {
            Ok(frame) => inner.deliver(frame),
            Err(error) => {
                // EOF or a protocol error: the child is gone. Every pending
                // request fails closed, the heartbeat stops and the reaper
                // kills/reaps the child; this reader never joins itself.
                inner.fail_generation(
                    libc::ECONNRESET,
                    format!("workspace FUSE helper control channel closed: {error}"),
                );
                return;
            }
        }
    }
}

fn heartbeat_writer(inner: Arc<Inner>) {
    let mut seq = 0u64;
    loop {
        if inner.stop.load(Ordering::Acquire) || inner.dead.load(Ordering::Acquire) {
            return;
        }
        seq = seq.wrapping_add(1);
        let frame = match Frame::request(inner.generation, 0, None, 0, &Body::Heartbeat(Heartbeat { seq })) {
            Ok(frame) => frame,
            Err(_) => return,
        };
        let written = {
            let mut heartbeat = lock(&inner.heartbeat);
            write_frame(&mut *heartbeat, &frame)
        };
        if written.is_err() {
            if inner.stop.load(Ordering::Acquire) {
                return;
            }
            inner.fail_generation(libc::ECONNRESET, "workspace FUSE helper heartbeat write failed");
            return;
        }
        thread::sleep(HEARTBEAT_INTERVAL);
    }
}

/// Bounded cancel worker: one thread for every abandoned freeze or mount, not
/// one per call; the child's operation deadline is the fail-closed backstop.
fn abort_worker(inner: Arc<Inner>, jobs: mpsc::Receiver<AbortJob>) {
    loop {
        let job = match jobs.recv_timeout(Duration::from_millis(100)) {
            Ok(job) => job,
            Err(RecvTimeoutError::Timeout) => {
                if inner.stop.load(Ordering::Acquire) || inner.dead.load(Ordering::Acquire) {
                    return;
                }
                continue;
            }
            Err(RecvTimeoutError::Disconnected) => return,
        };
        if inner.stop.load(Ordering::Acquire) || inner.dead.load(Ordering::Acquire) {
            return;
        }
        let (workspace, epoch, body) = match job {
            AbortJob::Freeze { workspace, epoch, op_id } => {
                (workspace, epoch, Body::AbortFreeze(AbortFreeze { op_id }))
            }
            AbortJob::Mount { workspace, request } => (workspace, 0, Body::AbortMount(AbortMount { request })),
        };
        let _ = inner.call(Some(workspace), epoch, body, ABORT_DEADLINE);
    }
}

/// One dedicated, detached worker: it never joins, never accepts new threads,
/// and kills/reaps exactly the one child after generation death. It also polls
/// the dead flag, so a full signal channel cannot lose the kill request.
fn reap_child(inner: Arc<Inner>, jobs: mpsc::Receiver<ReapRequest>) {
    loop {
        match jobs.recv_timeout(REAPER_TICK) {
            Ok(ReapRequest::GenerationDead) => break,
            Err(RecvTimeoutError::Timeout) => {
                if inner.dead.load(Ordering::Acquire) {
                    break;
                }
            }
            Err(RecvTimeoutError::Disconnected) => {
                if inner.dead.load(Ordering::Acquire) {
                    break;
                }
                return;
            }
        }
    }
    inner.reap_child_until_exit();
}

/// One freeze attempt whose operation id exists before the begin frame.
/// Dropping an attempt that never began aborts the op id, so an unanswered
/// `freeze_begin` cannot park the gate and the per-mount freeze slot.
pub struct FreezeAttempt {
    client: HelperClient,
    workspace: Uuid,
    epoch: i64,
    op_id: u64,
    armed: bool,
}

impl FreezeAttempt {
    pub fn op_id(&self) -> u64 {
        self.op_id
    }

    /// Send the begin frame and wait for the drain acknowledgement.
    pub fn begin(mut self, deadline: Duration) -> Result<RemoteFreezeToken, HelperError> {
        let reply = self.client.call(
            Some(self.workspace),
            self.epoch,
            Body::FreezeBegin(FreezeBegin { op_id: self.op_id }),
            deadline,
        );
        match reply {
            Ok(Body::Ok(_)) => {
                self.armed = false;
                Ok(RemoteFreezeToken {
                    client: self.client.clone(),
                    workspace: self.workspace,
                    epoch: self.epoch,
                    op_id: self.op_id,
                    finished: AtomicBool::new(false),
                })
            }
            Ok(other) => {
                let error = HelperError::protocol(format!("unexpected freeze reply `{}`", other.op()));
                self.abort();
                Err(error)
            }
            Err(error) => {
                self.abort();
                Err(error)
            }
        }
    }

    fn abort(&mut self) {
        if self.armed {
            self.armed = false;
            self.client.inner.queue_abort(AbortJob::Freeze {
                workspace: self.workspace,
                epoch: self.epoch,
                op_id: self.op_id,
            });
        }
    }
}

impl Drop for FreezeAttempt {
    fn drop(&mut self) {
        self.abort();
    }
}

/// One remote freeze grant.
///
/// The token is one-shot: [`RemoteFreezeToken::finish`] sends exactly one
/// `freeze_finish`. Dropping an unfinished token sends `abort_freeze`, which
/// the child treats as a fence, never as a successful thaw.
pub struct RemoteFreezeToken {
    client: HelperClient,
    workspace: Uuid,
    epoch: i64,
    op_id: u64,
    finished: AtomicBool,
}

impl RemoteFreezeToken {
    pub fn epoch(&self) -> i64 {
        self.epoch
    }

    pub fn op_id(&self) -> u64 {
        self.op_id
    }

    pub fn finish(&self, decision: FreezeDecision) -> Result<(), HelperError> {
        if self.finished.swap(true, Ordering::AcqRel) {
            return Err(HelperError::new(libc::EPERM, "freeze token was already finished"));
        }
        let thaw = decision == FreezeDecision::Thaw;
        let reply = self.client.call(
            Some(self.workspace),
            self.epoch,
            Body::FreezeFinish(FreezeFinish { op_id: self.op_id, epoch: self.epoch, thaw }),
            FREEZE_DEADLINE,
        );
        match reply {
            Ok(Body::Ok(_)) => Ok(()),
            Ok(other) => Err(HelperError::protocol(format!("unexpected freeze finish reply `{}`", other.op()))),
            Err(error) => Err(error),
        }
    }
}

impl Drop for RemoteFreezeToken {
    fn drop(&mut self) {
        if self.finished.swap(true, Ordering::AcqRel) {
            return;
        }
        // Queued on the bounded cancel worker so a drop in an async context
        // neither blocks nor spawns one thread per abandoned freeze. The child
        // fences the epoch even when this abort never arrives: its own freeze
        // deadline releases the decision as a fence, never as a thaw.
        self.client.inner.queue_abort(AbortJob::Freeze {
            workspace: self.workspace,
            epoch: self.epoch,
            op_id: self.op_id,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fill_socket_until_blocked(stream: &mut UnixStream) {
        let fd = stream.as_raw_fd();
        let chunk = [0u8; 4096];
        loop {
            // SAFETY: the test owns both ends of the socket pair and keeps the
            // peer alive for the whole test.
            let sent = unsafe { libc::send(fd, chunk.as_ptr().cast(), chunk.len(), libc::MSG_DONTWAIT) };
            if sent > 0 {
                continue;
            }
            let error = io::Error::last_os_error();
            assert!(
                matches!(error.raw_os_error(), Some(code) if code == libc::EAGAIN || code == libc::EWOULDBLOCK),
                "unexpected socket fill error: {error}"
            );
            return;
        }
    }

    #[test]
    fn control_mutex_admission_is_bounded_by_the_absolute_deadline() {
        let mutex = Mutex::new(0u8);
        let _held = mutex.lock().expect("hold test mutex");
        let started = Instant::now();
        let error = match lock_until(&mutex, || started + Duration::from_millis(50)) {
            Ok(_) => panic!("a held control mutex must not admit another writer after the deadline"),
            Err(error) => error,
        };
        assert_eq!(error.code, libc::ETIMEDOUT);
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn short_zero_budget_send_marks_terminal_before_releasing_the_control_guard() {
        struct Guard(Arc<AtomicBool>);

        impl Drop for Guard {
            fn drop(&mut self) {
                self.0.store(false, Ordering::SeqCst);
            }
        }

        let guard_alive = Arc::new(AtomicBool::new(true));
        let guard = Guard(guard_alive.clone());
        let mut attempts = 0;
        let mut terminal_calls = 0;
        let complete = send_complete_or_terminal(
            &[1u8, 2, 3],
            |_, _| {
                attempts += 1;
                Err(io::Error::from_raw_os_error(libc::EINTR))
            },
            |code| {
                terminal_calls += 1;
                assert!(guard_alive.load(Ordering::SeqCst), "terminal marking must precede guard release");
                assert_eq!(code, libc::EINTR);
            },
        );
        assert!(!complete);
        assert_eq!(attempts, 1, "the zero-budget send must not retry EINTR or a short write");
        assert_eq!(terminal_calls, 1);
        drop(guard);
        assert!(!guard_alive.load(Ordering::SeqCst));
    }

    #[test]
    fn short_positive_zero_budget_send_terminalizes_with_eio() {
        let mut attempts = 0;
        let mut terminal_calls = 0;
        let complete = send_complete_or_terminal(
            &[1u8, 2, 3],
            |_, _| {
                attempts += 1;
                Ok(2)
            },
            |code| {
                terminal_calls += 1;
                assert_eq!(code, libc::EIO);
            },
        );
        assert!(!complete);
        assert_eq!(attempts, 1, "a short positive send must not be retried");
        assert_eq!(terminal_calls, 1);
    }

    #[test]
    fn stalled_control_write_observes_a_teardown_deadline_published_during_the_write() {
        let (mut writer, _reader) = UnixStream::pair().expect("socket pair");
        fill_socket_until_blocked(&mut writer);

        let published = Arc::new(Mutex::new(None));
        let publisher = published.clone();
        let release = thread::spawn(move || {
            thread::sleep(Duration::from_millis(20));
            *publisher.lock().expect("publish teardown deadline") = Some(Instant::now() + Duration::from_millis(30));
        });

        let call_deadline = Instant::now() + Duration::from_secs(5);
        let started = Instant::now();
        let bytes = [0u8; 4096];
        let error = match write_bytes_until(&mut writer, &bytes, || match *published.lock().expect("read deadline") {
            Some(teardown) => call_deadline.min(teardown),
            None => call_deadline,
        }) {
            Ok(()) => panic!("a full send buffer with no reader must not report a clean write"),
            Err(error) => error,
        };
        release.join().expect("publisher thread");

        assert_eq!(error.code, libc::ETIMEDOUT);
        assert!(started.elapsed() >= Duration::from_millis(15), "teardown publication was not exercised");
        assert!(started.elapsed() < Duration::from_secs(2), "write ignored the published teardown cap");
    }
}
