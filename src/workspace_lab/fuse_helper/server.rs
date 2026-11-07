//! Child side of the independent FUSE helper.
//!
//! The child is started by `main --workspace-fuse-helper` before `Config`,
//! PostgreSQL, `Store` or the volume lock exist. It only knows the inherited
//! control (fd 0) and heartbeat (fd 1) sockets and the S3/lazy environment the
//! parent chose to forward.
//!
//! Threads:
//!
//! * the control loop owns the reader: it decodes frames and answers the short
//!   gate queries itself, so a slow mount, unmount, prewarm or session join can
//!   never delay a marker, handoff, finish or heartbeat,
//! * two bounded worker pools run the blocking operations (mount/unmount and
//!   prewarm) with a fixed number of slots; a full pool is an immediate
//!   `EBUSY`, never an unbounded thread,
//! * one heartbeat reader updates the watchdog deadline,
//! * one watchdog fences and exits when the deadline passes,
//! * one freeze thread per granted freeze (at most one per mount), never one
//!   per cancel,
//! * one FUSE actor thread per mount plus the process-wide read pool created by
//!   `fuse_dispatch`.
//!
//! Every operation that can outlive its caller has an independent child-side
//! deadline. A missing cancel, a lost begin reply or a dead control socket
//! therefore releases the gate as a fence and frees the per-mount operation
//! slot; no path relies on EOF to clean up.
//!
//! Failure policy: a panic, a heartbeat EOF, a missed heartbeat deadline or a
//! lost control socket fences every gate (including gates of mounts that are
//! still being built), drops every freeze waiter (a dropped waiter is a fence,
//! never a thaw), unmounts every workspace and exits non-zero. An explicit
//! `shutdown` is the only exit that reports success.
use super::protocol::{
    Body, ErrorReply, FenceIfUnchanged, Frame, FreezeBegin, FreezeFinish, HEARTBEAT_DEADLINE, Handoff, Heartbeat,
    Hello, MOUNT_OP_DEADLINE, Observe, OkReply, PREWARM_DEADLINE, PROTOCOL_VERSION, Prewarm, StateReply, read_frame,
    write_frame,
};
use crate::workspace_lab::fuse_mount::{MountHandle, MutationGate};
use crate::workspaces::lazy::Reader;
use std::{
    collections::{HashMap, VecDeque},
    io,
    os::fd::{FromRawFd, OwnedFd},
    os::unix::net::UnixStream,
    path::PathBuf,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{self, Receiver, SyncSender},
    },
    thread,
    time::{Duration, Instant},
};
use uuid::Uuid;

#[path = "server_ops.rs"]
mod ops;

/// Per-mount operation queue, mirrored from `fuse_dispatch` for diagnostics.
pub(super) const MOUNT_QUEUE_CAPACITY: u32 = 128;
const WATCHDOG_TICK: Duration = Duration::from_millis(100);
/// After a freeze drain misses its deadline the gate is fenced and the begin is
/// cancelled; if the freeze thread still cannot leave the drain (an admitted
/// IO that never returns) the helper fail-stops instead of pretending a drain.
const FREEZE_JOIN_GRACE: Duration = Duration::from_secs(5);
/// Blocking operations run beside the control reader; four slots per pool keep
/// a burst of mounts from multiplying threads or starving heartbeats.
const OPS_WORKERS: usize = 4;
const PREWARM_WORKERS: usize = 4;
const OPS_QUEUE: usize = 16;
const PREWARM_QUEUE: usize = 8;
/// AbortMount cleanup is separate from the mount/unmount pool: a full ops
/// queue must never make the control reader run a slow session join inline.
/// One worker with a small bounded queue absorbs a cancel burst; if both
/// bounded queues are full the helper fail-stops instead of spawning threads.
const CLEANUP_WORKERS: usize = 1;
const CLEANUP_QUEUE: usize = 8;
/// Bounded memory of cancelled operation ids, so a cancel that races ahead of
/// its begin/mount frame cannot be forgotten and a late frame cannot revive it.
pub(super) const TOMBSTONES: usize = 64;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// One blocking job. `Box<dyn FnOnce>` keeps the pools type-agnostic.
pub(super) type Job = Box<dyn FnOnce() + Send + 'static>;

pub(super) struct Mounted {
    pub handle: MountHandle,
    pub gate: Arc<MutationGate>,
    pub reader: Option<Arc<Reader>>,
    /// Canonical root the mount was built from, for an idempotent retry.
    pub root: PathBuf,
    /// Mount frame that currently owns this registration. A cancel only tears
    /// down the mount it names, and an idempotent retry takes ownership so a
    /// delayed cancel of the previous frame cannot remove the confirmed mount.
    pub request: u64,
}

/// A mount that has been admitted but not published. The gate is registered
/// here as soon as it exists so the watchdog can fence a half-built mount.
pub(super) struct PendingMount {
    pub request: u64,
    pub deadline: Instant,
    pub cancelled: Arc<AtomicBool>,
    pub gate: Option<Arc<MutationGate>>,
}

pub(super) struct FreezeOp {
    pub workspace: Uuid,
    pub epoch: i64,
    /// Begin frame that owns this op; a cancel or finish must address the same
    /// workspace/epoch and removal is conditional on this request.
    pub begin_request: u64,
    pub deadline: Instant,
    pub failstop_at: Instant,
    pub expired: AtomicBool,
    pub decision: SyncSender<bool>,
    /// Request id that receives the `finished` reply once the gate is free.
    pub done: Arc<Mutex<Option<u64>>>,
    pub released: AtomicBool,
}

pub(super) struct State {
    pub generation: AtomicU64,
    pub hello: AtomicBool,
    pub last_heartbeat: Mutex<Instant>,
    pub control: Mutex<UnixStream>,
    pub mounts: Mutex<HashMap<Uuid, Mounted>>,
    pub pending: Mutex<HashMap<Uuid, PendingMount>>,
    pub mount_tombstones: Mutex<VecDeque<(Uuid, u64)>>,
    pub freezes: Mutex<HashMap<u64, FreezeOp>>,
    pub freeze_tombstones: Mutex<VecDeque<u64>>,
    pub ops: SyncSender<Job>,
    pub prewarm: SyncSender<Job>,
    pub cleanup: SyncSender<Job>,
}

impl State {
    fn new(control: UnixStream, ops: SyncSender<Job>, prewarm: SyncSender<Job>, cleanup: SyncSender<Job>) -> Self {
        Self {
            generation: AtomicU64::new(0),
            hello: AtomicBool::new(false),
            last_heartbeat: Mutex::new(Instant::now()),
            control: Mutex::new(control),
            mounts: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            mount_tombstones: Mutex::new(VecDeque::new()),
            freezes: Mutex::new(HashMap::new()),
            freeze_tombstones: Mutex::new(VecDeque::new()),
            ops,
            prewarm,
            cleanup,
        }
    }

    /// Fence every published mount and every gate that is still being built.
    fn fence_all(&self) {
        let pending: Vec<Arc<MutationGate>> = {
            let pending = lock(&self.pending);
            pending.values().filter_map(|entry| entry.gate.clone()).collect()
        };
        let mounted: Vec<Arc<MutationGate>> = {
            let mounts = lock(&self.mounts);
            mounts.values().map(|mount| mount.gate.clone()).collect()
        };
        for gate in pending.into_iter().chain(mounted) {
            gate.fence();
        }
    }

    /// Dropping the senders makes every waiting freeze pick the fence branch.
    fn release_freezes(&self) {
        lock(&self.freezes).clear();
    }

    /// Fence first (via the caller), then cancel pending work and unmount one
    /// mount at a time so a slow session join cannot hold the mount registry.
    fn unmount_all(&self) {
        {
            let pending = lock(&self.pending);
            for entry in pending.values() {
                entry.cancelled.store(true, Ordering::Release);
            }
        }
        let mounts: Vec<Mounted> = {
            let mut mounts = lock(&self.mounts);
            mounts.drain().map(|(_, mount)| mount).collect()
        };
        for mount in mounts {
            mount.handle.shutdown();
            drop(mount.handle);
        }
    }

    fn failstop(&self, reason: &str, code: i32) -> ! {
        failstop(self, reason, code)
    }
}

fn send(state: &State, request_id: u64, workspace: Option<Uuid>, db_epoch: i64, body: &Body) -> io::Result<()> {
    let generation = state.generation.load(Ordering::Acquire);
    let frame = Frame::request(generation, request_id, workspace, db_epoch, body)?;
    let mut control = lock(&state.control);
    write_frame(&mut *control, &frame)
}

fn reply(state: &State, request_id: u64, workspace: Option<Uuid>, db_epoch: i64, body: Body) {
    let _ = send(state, request_id, workspace, db_epoch, &body);
}

fn reply_error(state: &State, request_id: u64, workspace: Option<Uuid>, code: i32, message: impl Into<String>) {
    reply(state, request_id, workspace, 0, Body::Error(ErrorReply { code, message: message.into() }));
}

fn reply_errno(state: &State, request_id: u64, workspace: Option<Uuid>, error: io::Error) {
    let code = error.raw_os_error().unwrap_or(libc::EIO);
    reply_error(state, request_id, workspace, code, error.to_string());
}

fn phase_name(phase: crate::workspace_lab::mutation_gate::GatePhase) -> &'static str {
    match phase {
        crate::workspace_lab::mutation_gate::GatePhase::Healthy => "healthy",
        crate::workspace_lab::mutation_gate::GatePhase::Frozen => "frozen",
        crate::workspace_lab::mutation_gate::GatePhase::Fenced => "fenced",
    }
}

fn state_reply(gate: &MutationGate, outcome: Option<&str>, applied: Option<bool>) -> StateReply {
    StateReply {
        epoch: gate.epoch(),
        generation: gate.generation(),
        phase: phase_name(gate.phase()).to_owned(),
        writable_until: gate.writable_until(),
        outcome: outcome.map(str::to_owned),
        applied,
    }
}

fn gate_for(state: &State, workspace: Uuid) -> Option<Arc<MutationGate>> {
    lock(&state.mounts).get(&workspace).map(|mount| mount.gate.clone())
}

/// Entry point used by `main` before any service initialisation.
pub fn run() -> io::Result<()> {
    if !cfg!(target_os = "linux") {
        return Err(io::Error::new(io::ErrorKind::Unsupported, "workspace FUSE helper requires Linux"));
    }
    let control = stream_from_fd(0)?;
    let heartbeat = stream_from_fd(1)?;
    let reader = control.try_clone()?;
    let (ops, ops_jobs) = mpsc::sync_channel::<Job>(OPS_QUEUE);
    let (prewarm, prewarm_jobs) = mpsc::sync_channel::<Job>(PREWARM_QUEUE);
    let (cleanup, cleanup_jobs) = mpsc::sync_channel::<Job>(CLEANUP_QUEUE);
    let state = Arc::new(State::new(control, ops, prewarm, cleanup));

    // Child-only panic policy: a panic may already hold the state, mount or
    // gate mutex, so the hook must not fence, unmount, join or format output.
    // `_exit` is the only lock-free, non-returnable fail-stop here; the kernel
    // closes every inherited and FUSE descriptor, which aborts each session.
    install_panic_failstop();

    spawn_pool(state.clone(), "fuse-helper-op", OPS_WORKERS, ops_jobs)?;
    spawn_pool(state.clone(), "fuse-helper-prewarm", PREWARM_WORKERS, prewarm_jobs)?;
    spawn_pool(state.clone(), "fuse-helper-cleanup", CLEANUP_WORKERS, cleanup_jobs)?;
    let watchdog_state = state.clone();
    thread::Builder::new().name("fuse-helper-watchdog".into()).spawn(move || watchdog(watchdog_state))?;
    let heartbeat_state = state.clone();
    thread::Builder::new()
        .name("fuse-helper-heartbeat-reader".into())
        .spawn(move || heartbeat_reader(heartbeat_state, heartbeat))?;

    let loop_state = state.clone();
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| control_loop(loop_state, reader)));
    match outcome {
        // An explicit shutdown was acknowledged and handed to a worker that
        // fences, unmounts and exits 0. This thread only waits for it; if the
        // worker panics the job guard calls failstop instead of hanging.
        Ok(Ok(LoopOutcome::Shutdown)) => loop {
            thread::park_timeout(Duration::from_secs(1));
        },
        Ok(Ok(LoopOutcome::Closed)) => teardown(&state, "control loop closed", 1),
        Ok(Err(_)) => teardown(&state, "control loop failed", 1),
        Err(_) => teardown(&state, "control loop panicked", 1),
    }
}

/// Exit code for a child panic fail-stop. `libtest` also uses 101 for a failed
/// test, but the subprocess fixture additionally proves the old self-locking
/// fence path is gone by holding a state mutex across the panic.
const PANIC_FAILSTOP_EXIT: i32 = 101;

/// Child-only lock-free panic fail-stop.
///
/// A panic can interrupt any thread while it owns `state.mounts`,
/// `state.pending` or a gate mutex. Taking one of those locks here would
/// deadlock the process instead of stopping it. `_exit` never returns, never
/// runs destructors or joins, and makes the kernel close every FUSE descriptor
/// so no mount can keep admitting writes. A normal `shutdown` still exits 0.
fn install_panic_failstop() {
    std::panic::set_hook(Box::new(|_info| {
        // SAFETY: `_exit` is async-signal-safe and does not touch Rust state.
        unsafe { libc::_exit(PANIC_FAILSTOP_EXIT) };
    }));
}

/// Route one AbortMount cleanup off the control reader. The ops pool is tried
/// first so normal capacity keeps one cancel isolated to its own mount; a
/// dedicated bounded cleanup worker absorbs an ops-pool burst. `Err` means both
/// bounded queues are full and the caller must fail-stop, never run the slow
/// session join inline and never spawn an unbounded thread.
fn send_abort_job(ops: &SyncSender<Job>, cleanup: &SyncSender<Job>, job: Job) -> Result<(), Job> {
    match ops.try_send(job) {
        Ok(()) => Ok(()),
        Err(mpsc::TrySendError::Full(job) | mpsc::TrySendError::Disconnected(job)) => match cleanup.try_send(job) {
            Ok(()) => Ok(()),
            Err(mpsc::TrySendError::Full(job) | mpsc::TrySendError::Disconnected(job)) => Err(job),
        },
    }
}

fn spawn_pool(state: Arc<State>, name: &str, workers: usize, jobs: Receiver<Job>) -> io::Result<()> {
    let jobs = Arc::new(Mutex::new(jobs));
    for index in 0..workers {
        let state = state.clone();
        let jobs = jobs.clone();
        thread::Builder::new().name(format!("{name}-{index}")).spawn(move || {
            loop {
                let job = match lock(&jobs).recv() {
                    Ok(job) => job,
                    Err(_) => return,
                };
                if std::panic::catch_unwind(std::panic::AssertUnwindSafe(job)).is_err() {
                    state.failstop("operation worker panicked", 1);
                }
            }
        })?;
    }
    Ok(())
}

fn stream_from_fd(fd: i32) -> io::Result<UnixStream> {
    // SAFETY: the parent installs exactly these two descriptors with
    // `Stdio::from(OwnedFd)` for the helper child, and this function runs in
    // that child only, before any other owner could exist.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    Ok(UnixStream::from(owned))
}

fn watchdog(state: Arc<State>) {
    loop {
        thread::sleep(WATCHDOG_TICK);
        let elapsed = lock(&state.last_heartbeat).elapsed();
        if elapsed > HEARTBEAT_DEADLINE {
            // The parent may be SIGKILLed while another thread still holds the
            // socket open, so EOF alone is not a liveness signal.
            teardown(&state, "heartbeat deadline missed", 1);
        }
        enforce_freeze_deadlines(&state);
    }
}

/// A freeze can block inside `begin_freeze` while an admitted mutation never
/// drains; the waiter deadline alone would never fire there. The watchdog does
/// it independently: fence the gate, cancel the begin and release the decision
/// as a fence. If the thread still cannot leave the drain, exit the helper.
fn enforce_freeze_deadlines(state: &State) {
    let now = Instant::now();
    let expired: Vec<(u64, Uuid, i64, u64, Instant)> = {
        let freezes = lock(&state.freezes);
        freezes
            .iter()
            .filter(|(_, op)| op.deadline <= now)
            .map(|(op_id, op)| (*op_id, op.workspace, op.epoch, op.begin_request, op.failstop_at))
            .collect()
    };
    for (op_id, workspace, _epoch, begin_request, failstop_at) in expired {
        // Fence once per operation. A thaw already buffered in the decision
        // channel cannot revive a fenced gate, so reply with a timeout instead
        // of ever reporting a drained gate.
        let first = {
            let freezes = lock(&state.freezes);
            match freezes.get(&op_id) {
                Some(op) => {
                    if op.expired.swap(true, Ordering::AcqRel) {
                        false
                    } else {
                        // Release the decision as a fence when the drain is
                        // still stuck; a thaw already buffered stays harmless
                        // because the gate is fenced below.
                        let _ = op.decision.send(false);
                        true
                    }
                }
                None => continue,
            }
        };
        if first {
            if let Some(gate) = gate_for(state, workspace) {
                gate.fence();
            }
            reply_error(
                state,
                begin_request,
                Some(workspace),
                libc::ETIMEDOUT,
                "freeze drain deadline expired; the epoch stays fenced",
            );
        }
        if now >= failstop_at {
            // The drain still did not release: bounded fail-stop, never a
            // healthy reply and never an unbounded wait for the IO.
            failstop(&state, "freeze drain could not be released within its deadline", 1);
        }
    }
}

fn failstop(state: &State, reason: &str, code: i32) -> ! {
    // Do not join FUSE sessions here: the point of this path is that an
    // admitted IO may never return. Fencing and process exit are the bounded
    // termination; the kernel aborts the mount when the descriptors close.
    eprintln!("rootyard: workspace FUSE helper {reason}; fencing before fail-stop");
    state.fence_all();
    state.release_freezes();
    std::process::exit(code)
}

fn heartbeat_reader(state: Arc<State>, mut stream: UnixStream) {
    loop {
        let frame = match read_frame(&mut stream) {
            Ok(frame) => frame,
            Err(_) => teardown(&state, "heartbeat socket closed", 1),
        };
        if !matches!(frame.body(), Ok(Body::Heartbeat(Heartbeat { .. }))) {
            teardown(&state, "unexpected heartbeat frame", 1);
        }
        let generation = state.generation.load(Ordering::Acquire);
        if state.hello.load(Ordering::Acquire) && frame.generation != generation {
            teardown(&state, "heartbeat generation mismatch", 1);
        }
        *lock(&state.last_heartbeat) = Instant::now();
    }
}

fn teardown(state: &State, reason: &str, code: i32) -> ! {
    eprintln!("rootyard: workspace FUSE helper {reason}; fencing every workspace before exit");
    state.fence_all();
    state.release_freezes();
    state.unmount_all();
    std::process::exit(code)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoopOutcome {
    /// The control socket closed or failed without an explicit shutdown.
    Closed,
    /// A `shutdown` frame was acknowledged; a worker owns the teardown.
    Shutdown,
}

fn control_loop(state: Arc<State>, mut stream: UnixStream) -> io::Result<LoopOutcome> {
    loop {
        let frame = read_frame(&mut stream)?;
        if !state.hello.load(Ordering::Acquire) {
            match frame.body() {
                Ok(Body::Hello(Hello { version, .. })) => {
                    if version != PROTOCOL_VERSION {
                        reply_error(&state, frame.request_id, None, libc::EPROTO, "unsupported helper protocol");
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "protocol mismatch"));
                    }
                    state.generation.store(frame.generation, Ordering::Release);
                    state.hello.store(true, Ordering::Release);
                    *lock(&state.last_heartbeat) = Instant::now();
                    reply(&state, frame.request_id, None, 0, Body::Ok(OkReply { op_id: None }));
                }
                _ => {
                    reply_error(&state, frame.request_id, None, libc::EPROTO, "helper handshake required");
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "frame before handshake"));
                }
            }
            continue;
        }
        if frame.generation != state.generation.load(Ordering::Acquire) {
            reply_error(&state, frame.request_id, frame.workspace, libc::ESTALE, "stale helper generation");
            continue;
        }
        let body = match frame.body() {
            Ok(body) => body,
            Err(error) => {
                reply_error(&state, frame.request_id, frame.workspace, libc::EPROTO, error.to_string());
                continue;
            }
        };
        if let Some(outcome) = dispatch(&state, frame.request_id, frame.workspace, frame.db_epoch, body) {
            return Ok(outcome);
        }
    }
}

/// Returns `Some` when the control loop must stop reading.
fn dispatch(
    state: &Arc<State>,
    request: u64,
    workspace: Option<Uuid>,
    db_epoch: i64,
    body: Body,
) -> Option<LoopOutcome> {
    // Capture the absolute admission time before a job is queued: queue delay
    // is part of the caller's budget, not free time for the worker.
    let admitted = Instant::now();
    match body {
        Body::Heartbeat(_) => {
            *lock(&state.last_heartbeat) = Instant::now();
        }
        Body::Mount(request_body) => {
            let job_state = state.clone();
            let deadline = admitted + MOUNT_OP_DEADLINE;
            let job: Job =
                Box::new(move || ops::mount(&job_state, request, workspace, db_epoch, request_body, deadline));
            if state.ops.try_send(job).is_err() {
                reply_error(state, request, workspace, libc::EBUSY, "workspace FUSE helper operation slots are full");
            }
        }
        Body::Unmount => {
            let job_state = state.clone();
            let job: Job = Box::new(move || ops::unmount(&job_state, request, workspace));
            if state.ops.try_send(job).is_err() {
                reply_error(state, request, workspace, libc::EBUSY, "workspace FUSE helper operation slots are full");
            }
        }
        Body::AbortMount(abort) => {
            // Cancel the exact mount frame on the reader thread so a pending
            // mount cannot publish after this point; the slow session teardown
            // is handed to a worker.
            let removed = ops::cancel_mount(state, workspace, abort.request);
            let job_state = state.clone();
            let job: Job = Box::new(move || ops::abort_mount_reply(&job_state, request, workspace, removed));
            match send_abort_job(&state.ops, &state.cleanup, job) {
                Ok(()) => {}
                // The synchronous cancel/fence above already happened. Both
                // bounded queues are full, so an inline join would stall every
                // workspace on the control reader: fail-stop closes the FUSE
                // descriptors instead.
                Err(_job) => failstop(state, "abort mount cleanup capacity exhausted", 1),
            }
        }
        Body::Handoff(Handoff { epoch, until }) => match workspace.and_then(|ws| gate_for(state, ws)) {
            Some(gate) => match gate.handoff(epoch, until) {
                Ok(()) => reply(state, request, workspace, epoch, Body::Ok(OkReply { op_id: None })),
                Err(error) => reply_errno(state, request, workspace, error),
            },
            None => reply_error(state, request, workspace, libc::ENOENT, "workspace is not mounted"),
        },
        Body::Marker => match workspace.and_then(|ws| gate_for(state, ws)) {
            Some(gate) => reply(state, request, workspace, 0, Body::State(state_reply(&gate, None, None))),
            None => reply_error(state, request, workspace, libc::ENOENT, "workspace is not mounted"),
        },
        Body::Observe(Observe { epoch, until }) => match workspace.and_then(|ws| gate_for(state, ws)) {
            Some(gate) => {
                let outcome = match gate.observe_lease(epoch, until) {
                    crate::workspace_lab::mutation_gate::LeaseObservation::Stale => "stale",
                    crate::workspace_lab::mutation_gate::LeaseObservation::Renewed => "renewed",
                    crate::workspace_lab::mutation_gate::LeaseObservation::Blocked => "blocked",
                    crate::workspace_lab::mutation_gate::LeaseObservation::Fenced => "fenced",
                };
                reply(state, request, workspace, epoch, Body::State(state_reply(&gate, Some(outcome), None)));
            }
            None => reply_error(state, request, workspace, libc::ENOENT, "workspace is not mounted"),
        },
        Body::FenceIfUnchanged(FenceIfUnchanged { epoch, generation }) => {
            match workspace.and_then(|ws| gate_for(state, ws)) {
                Some(gate) => {
                    let applied = gate.fence_if_unchanged((epoch, generation));
                    reply(state, request, workspace, epoch, Body::State(state_reply(&gate, None, Some(applied))));
                }
                None => reply_error(state, request, workspace, libc::ENOENT, "workspace is not mounted"),
            }
        }
        Body::FreezeBegin(FreezeBegin { op_id }) => ops::freeze_begin(state, request, workspace, db_epoch, op_id),
        Body::FreezeFinish(FreezeFinish { op_id, epoch, thaw }) => {
            ops::freeze_release(state, request, workspace, op_id, db_epoch, epoch, thaw)
        }
        Body::AbortFreeze(crate::workspace_lab::fuse_helper::protocol::AbortFreeze { op_id }) => {
            ops::freeze_release(state, request, workspace, op_id, db_epoch, -1, false)
        }
        Body::Prewarm(Prewarm { paths }) => {
            let job_state = state.clone();
            let deadline = admitted + PREWARM_DEADLINE;
            let job: Job = Box::new(move || ops::prewarm(&job_state, request, workspace, paths, deadline));
            if state.prewarm.try_send(job).is_err() {
                reply_error(state, request, workspace, libc::EBUSY, "workspace FUSE helper prewarm slots are full");
            }
        }
        Body::Shutdown => {
            reply(state, request, None, 0, Body::ShuttingDown);
            let job_state = state.clone();
            let job: Job = Box::new(move || teardown(&job_state, "explicit shutdown", 0));
            if state.ops.try_send(job).is_err() {
                teardown(state, "shutdown could not be scheduled", 1);
            }
            return Some(LoopOutcome::Shutdown);
        }
        other => {
            reply_error(state, request, workspace, libc::EPROTO, format!("unexpected operation `{}`", other.op()));
        }
    }
    None
}

#[cfg(test)]
#[path = "server_tests.rs"]
mod tests;
