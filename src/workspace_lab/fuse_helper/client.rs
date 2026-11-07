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
    ABORT_DEADLINE, AbortFreeze, AbortMount, Body, ErrorReply, FenceIfUnchanged, Frame, FREEZE_DEADLINE,
    FreezeBegin, FreezeFinish, Handoff, HEARTBEAT_INTERVAL, Heartbeat, Hello, MAX_INFLIGHT, MOUNT_DEADLINE,
    MountRequest, Observe, PREWARM_DEADLINE, PROTOCOL_VERSION, Prewarm, PrewarmReply, REQUEST_DEADLINE,
    StateReply, read_frame, write_frame,
};
use crate::workspace_lab::fuse_mount::FreezeDecision;
use std::{
    collections::HashMap,
    io,
    os::{
        fd::OwnedFd,
        unix::{net::UnixStream, process::CommandExt},
    },
    path::Path,
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{self, RecvTimeoutError},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use uuid::Uuid;

/// Bound on queued cancel frames. One worker sends them, so a caller that
/// abandons a begin/mount can never spawn an unbounded number of threads.
const ABORT_QUEUE: usize = 64;

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

struct Inner {
    generation: u64,
    control: Mutex<UnixStream>,
    heartbeat: Mutex<UnixStream>,
    pending: Mutex<HashMap<u64, PendingReply>>,
    aborts: mpsc::SyncSender<AbortJob>,
    next_request: AtomicU64,
    dead: AtomicBool,
    stop: AtomicBool,
    child: Mutex<Option<Child>>,
    threads: Mutex<Vec<JoinHandle<()>>>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Inner {
    fn mark_dead(&self) {
        self.dead.store(true, Ordering::Release);
        let orphaned: Vec<PendingReply> = {
            let mut pending = lock(&self.pending);
            pending.drain().map(|(_, pending)| pending).collect()
        };
        for pending in orphaned {
            let _ = pending.sender.send(Err(HelperError::disconnected()));
        }
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
                Ok(body) if expected.db_epoch != 0 && frame.db_epoch != expected.db_epoch => Err(
                    HelperError::protocol("helper reply does not match the request epoch"),
                ),
                Ok(body) => Ok(body),
                Err(error) => Err(HelperError::protocol(error.to_string())),
            }
        };
        let _ = expected.sender.send(result);
    }

    fn queue_abort(&self, job: AbortJob) {
        // Non-blocking by design: the child-side operation deadline covers a
        // full queue, and a dead helper has nothing left to cancel. This is
        // what keeps a dropped freeze token from spawning one thread per call.
        let _ = self.aborts.try_send(job);
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
        deadline: Duration,
    ) -> (u64, Result<Body, HelperError>) {
        if self.dead.load(Ordering::Acquire) {
            return (0, Err(HelperError::disconnected()));
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
        let written = {
            // Only the write of this frame is under the mutex; the reply is
            // awaited with the lock released so one slow operation cannot
            // serialize every other mount's control traffic.
            let mut control = lock(&self.control);
            write_frame(&mut *control, &frame)
        };
        if let Err(error) = written {
            lock(&self.pending).remove(&request_id);
            self.mark_dead();
            return (
                request_id,
                Err(HelperError::new(libc::ECONNRESET, format!("helper control write failed: {error}"))),
            );
        }
        match receiver.recv_timeout(deadline) {
            Ok(result) => (request_id, result),
            Err(RecvTimeoutError::Timeout) => {
                lock(&self.pending).remove(&request_id);
                (
                    request_id,
                    Err(HelperError::new(libc::ETIMEDOUT, "workspace FUSE helper request deadline expired")),
                )
            }
            Err(RecvTimeoutError::Disconnected) => (request_id, Err(HelperError::disconnected())),
        }
    }

    fn call(&self, workspace: Option<Uuid>, db_epoch: i64, body: Body, deadline: Duration) -> Result<Body, HelperError> {
        self.call_full(workspace, db_epoch, body, deadline).1
    }

    fn wait_exit(&self, grace: Duration) -> Result<(), HelperError> {
        let deadline = Instant::now() + grace;
        loop {
            let status = {
                let mut child = lock(&self.child);
                match child.as_mut() {
                    Some(child) => child.try_wait(),
                    None => return Ok(()),
                }
            };
            match status {
                Ok(Some(status)) if status.success() => return Ok(()),
                Ok(Some(status)) => {
                    return Err(HelperError::new(
                        libc::ECHILD,
                        format!("workspace FUSE helper exited with {status}"),
                    ));
                }
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
                Ok(None) => {
                    let mut child = lock(&self.child);
                    if let Some(child) = child.as_mut() {
                        let _ = child.kill();
                        let _ = child.wait();
                    }
                    return Err(HelperError::new(
                        libc::ETIMEDOUT,
                        "workspace FUSE helper did not exit within the shutdown grace",
                    ));
                }
                Err(error) => return Err(HelperError::new(libc::ECHILD, error.to_string())),
            }
        }
    }

    fn join_threads(&self) {
        let threads: Vec<JoinHandle<()>> = std::mem::take(&mut *lock(&self.threads));
        for handle in threads {
            let _ = handle.join();
        }
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(mut child) = self.child.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take() {
            // The child watchdog also fences and exits on its own when the
            // heartbeat stops; killing here only avoids a stray process while
            // the parent is being torn down by tests or a panic.
            let _ = child.kill();
            let _ = child.wait();
        }
        self.mark_dead();
        self.join_threads();
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
        let (aborts, abort_jobs) = mpsc::sync_channel(ABORT_QUEUE);
        let inner = Arc::new(Inner {
            generation,
            control: Mutex::new(control),
            heartbeat: Mutex::new(heartbeat_stream),
            pending: Mutex::new(HashMap::new()),
            aborts,
            next_request: AtomicU64::new(1),
            dead: AtomicBool::new(false),
            stop: AtomicBool::new(false),
            child: Mutex::new(Some(child)),
            threads: Mutex::new(Vec::new()),
        });

        let reader_inner = inner.clone();
        let reader = thread::Builder::new()
            .name("fuse-helper-control-reader".into())
            .spawn(move || control_reader(reader_inner, reader_stream))?;
        let heartbeat_inner = inner.clone();
        let heartbeat = thread::Builder::new()
            .name("fuse-helper-heartbeat".into())
            .spawn(move || heartbeat_writer(heartbeat_inner))?;
        let abort_inner = inner.clone();
        let aborts = thread::Builder::new()
            .name("fuse-helper-freeze-abort".into())
            .spawn(move || abort_worker(abort_inner, abort_jobs))?;
        let mut threads = lock(&inner.threads);
        threads.push(reader);
        threads.push(heartbeat);
        threads.push(aborts);
        drop(threads);
        Ok(Self { inner })
    }

    pub fn generation(&self) -> u64 {
        self.inner.generation
    }

    /// False after control EOF, a failed write or a completed shutdown.
    pub fn alive(&self) -> bool {
        !self.inner.dead.load(Ordering::Acquire)
    }

    /// Send one request and wait for the matching reply with a deadline.
    pub fn call(&self, workspace: Option<Uuid>, db_epoch: i64, body: Body, deadline: Duration) -> Result<Body, HelperError> {
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
        let root = root
            .to_str()
            .ok_or_else(|| HelperError::new(libc::EINVAL, "storage root is not valid UTF-8"))?
            .to_owned();
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
            self.inner.queue_abort(AbortJob::Mount { workspace, request: request_id });
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
        FreezeAttempt {
            client: self.clone(),
            workspace,
            epoch,
            op_id: self.inner.next_request(),
            armed: true,
        }
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
        let reply = self.call(Some(workspace), 0, Body::Unmount, MOUNT_DEADLINE)?;
        match reply {
            Body::Unmounted => Ok(()),
            other => Err(HelperError::protocol(format!("unexpected unmount reply `{}`", other.op()))),
        }
    }

    /// Ask the child to fence, unmount and exit, then reap it within `grace`.
    ///
    /// A helper that does not exit is killed and reported as an error: shutdown
    /// either observes a real exit or fails, it never claims success.
    pub fn shutdown(&self, grace: Duration) -> Result<(), HelperError> {
        let request = self.call(None, 0, Body::Shutdown, grace.min(REQUEST_DEADLINE));
        self.inner.stop.store(true, Ordering::Release);
        match self.inner.wait_exit(grace) {
            Ok(()) => {
                self.inner.mark_dead();
                self.inner.join_threads();
                match request {
                    Ok(Body::ShuttingDown) | Err(HelperError { code: libc::ECONNRESET, .. }) => Ok(()),
                    Ok(other) => Err(HelperError::protocol(format!(
                        "unexpected shutdown reply `{}`",
                        other.op()
                    ))),
                    Err(error) => Err(error),
                }
            }
            Err(error) => {
                self.inner.mark_dead();
                self.inner.join_threads();
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
            Err(_) => {
                // EOF or a protocol error: the child is gone. Every pending
                // request fails closed and `alive()` turns false.
                inner.mark_dead();
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
            inner.mark_dead();
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
        let (workspace, epoch, body) = match job {
            AbortJob::Freeze { workspace, epoch, op_id } => (
                workspace,
                epoch,
                Body::AbortFreeze(AbortFreeze { op_id }),
            ),
            AbortJob::Mount { workspace, request } => (workspace, 0, Body::AbortMount(AbortMount { request })),
        };
        let _ = inner.call(Some(workspace), epoch, body, ABORT_DEADLINE);
    }
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
