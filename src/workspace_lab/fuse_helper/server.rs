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
    Body, ErrorReply, FenceIfUnchanged, Frame, FreezeBegin, FreezeFinish, Handoff, HEARTBEAT_DEADLINE, Heartbeat, Hello,
    MountRequest, Observe, OkReply, PROTOCOL_VERSION, Prewarm, StateReply, read_frame, write_frame,
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
/// Blocking operations run beside the control reader; four slots per pool keep
/// a burst of mounts from multiplying threads or starving heartbeats.
const OPS_WORKERS: usize = 4;
const PREWARM_WORKERS: usize = 4;
const OPS_QUEUE: usize = 16;
const PREWARM_QUEUE: usize = 8;
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
    pub decision: SyncSender<bool>,
    /// Request id that receives the `finished` reply once the gate is free.
    pub done: Mutex<Option<u64>>,
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
}

impl State {
    fn new(control: UnixStream, ops: SyncSender<Job>, prewarm: SyncSender<Job>) -> Self {
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
        teardown(self, reason, code)
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
    let state = Arc::new(State::new(control, ops, prewarm));

    // A panic anywhere in the child must fence before anything else: the hook
    // runs before unwinding continues, so a half-finished operation can never
    // leave a writable mount behind. Worker jobs are additionally guarded with
    // `catch_unwind` below so a panic turns into one failstop, not a live
    // process that pretends the mount is still healthy.
    let hook_state = state.clone();
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        hook_state.fence_all();
        hook_state.release_freezes();
        previous(info);
    }));

    spawn_pool(state.clone(), "fuse-helper-op", OPS_WORKERS, ops_jobs)?;
    spawn_pool(state.clone(), "fuse-helper-prewarm", PREWARM_WORKERS, prewarm_jobs)?;
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

fn spawn_pool(state: Arc<State>, name: &str, workers: usize, jobs: Receiver<Job>) -> io::Result<()> {
    let jobs = Arc::new(Mutex::new(jobs));
    for index in 0..workers {
        let state = state.clone();
        let jobs = jobs.clone();
        thread::Builder::new().name(format!("{name}-{index}")).spawn(move || loop {
            let job = match lock(&jobs).recv() {
                Ok(job) => job,
                Err(_) => return,
            };
            if std::panic::catch_unwind(std::panic::AssertUnwindSafe(job)).is_err() {
                state.failstop("operation worker panicked", 1);
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
    }
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
    match body {
        Body::Heartbeat(_) => {
            *lock(&state.last_heartbeat) = Instant::now();
        }
        Body::Mount(request_body) => {
            let job_state = state.clone();
            let job: Job = Box::new(move || ops::mount(&job_state, request, workspace, db_epoch, request_body));
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
            if let Err(error) = state.ops.try_send(job) {
                // The pool is full: run the bounded compensation here so the
                // cancelled session is still joined instead of leaked.
                match error {
                    mpsc::TrySendError::Full(job) | mpsc::TrySendError::Disconnected(job) => job(),
                }
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
            ops::freeze_release(state, request, workspace, op_id, epoch, thaw)
        }
        Body::AbortFreeze(crate::workspace_lab::fuse_helper::protocol::AbortFreeze { op_id }) => {
            ops::freeze_release(state, request, workspace, op_id, -1, false)
        }
        Body::Prewarm(Prewarm { paths }) => {
            let job_state = state.clone();
            let job: Job = Box::new(move || ops::prewarm(&job_state, request, workspace, paths));
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
mod tests {
    use super::*;

    fn test_state() -> Arc<State> {
        let (_parent, child) = UnixStream::pair().unwrap();
        let (ops, ops_jobs) = mpsc::sync_channel::<Job>(1);
        let (prewarm, prewarm_jobs) = mpsc::sync_channel::<Job>(1);
        // Keep the receivers alive for the lifetime of the state.
        std::mem::forget(ops_jobs);
        std::mem::forget(prewarm_jobs);
        Arc::new(State::new(child, ops, prewarm))
    }

    #[test]
    fn teardown_policy_can_only_fence() {
        // A dropped freeze waiter is a fence: the receiver sees `Err` and the
        // freeze thread applies `FreezeDecision::Fence`.
        let (sender, receiver) = mpsc::sync_channel::<bool>(1);
        drop(sender);
        assert!(receiver.recv().is_err());
    }

    #[test]
    fn operation_tombstones_are_bounded() {
        let state = test_state();
        for op_id in 0..(TOMBSTONES as u64 + 8) {
            ops::push_freeze_tombstone(&state, op_id);
            ops::push_mount_tombstone(&state, Uuid::nil(), op_id);
        }
        assert_eq!(lock(&state.freeze_tombstones).len(), TOMBSTONES);
        assert_eq!(lock(&state.mount_tombstones).len(), TOMBSTONES);
        // The oldest entry was evicted, the newest is still known.
        assert!(ops::take_freeze_tombstone(&state, 0));
        assert!(ops::take_freeze_tombstone(&state, TOMBSTONES as u64 + 7));
        assert!(!ops::take_freeze_tombstone(&state, TOMBSTONES as u64 + 7), "a tombstone is one-shot");
    }

    #[test]
    fn pending_mount_gate_is_fenced_without_being_published() {
        let state = test_state();
        let gate = MutationGate::new_with_lease(4, i64::MAX).unwrap();
        lock(&state.pending).insert(
            Uuid::nil(),
            PendingMount {
                request: 7,
                deadline: Instant::now() + Duration::from_secs(1),
                cancelled: Arc::new(AtomicBool::new(false)),
                gate: Some(gate.clone()),
            },
        );
        state.fence_all();
        assert!(gate.is_fenced(), "a half-built mount must be fenced by the watchdog path");
        assert!(ops::checkpoint(&AtomicBool::new(false), Instant::now() + Duration::from_secs(1)).is_ok());
        assert!(ops::checkpoint(&AtomicBool::new(true), Instant::now() + Duration::from_secs(1)).is_err());
        assert!(ops::checkpoint(&AtomicBool::new(false), Instant::now()).is_err());
    }
}
