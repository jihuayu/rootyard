//! Child side of the independent FUSE helper.
//!
//! The child is started by `main --workspace-fuse-helper` before `Config`,
//! PostgreSQL, `Store` or the volume lock exist. It only knows the inherited
//! control (fd 0) and heartbeat (fd 1) sockets and the S3/lazy environment the
//! parent chose to forward.
//!
//! Threads:
//!
//! * the control loop owns request dispatch; it must never block on a freeze or
//!   a hydration job,
//! * one heartbeat reader updates the watchdog deadline,
//! * one watchdog fences and exits when the deadline passes,
//! * one freeze thread per granted freeze, one blocking thread per prewarm,
//! * one FUSE actor thread per mount plus the process-wide read pool created by
//!   `fuse_dispatch`.
//!
//! Failure policy: a panic, a heartbeat EOF, a missed heartbeat deadline or a
//! lost control socket fences every gate, drops every freeze waiter (a dropped
//! waiter is a fence, never a thaw), unmounts every workspace and exits. The
//! parent then sees control EOF and reports those workspaces as no longer
//! mounted.
use super::protocol::{
    AbortFreeze, Body, ErrorReply, FenceIfUnchanged, Frame, FreezeBegin, FreezeFinish, Handoff, HEARTBEAT_DEADLINE,
    Heartbeat, Hello, MountRequest, MountedReply, Observe, OkReply, PROTOCOL_VERSION, Prewarm, PrewarmReply, StateReply,
    read_frame, write_frame,
};
use super::{validate_root, workspace_paths};
use crate::{
    workspace_lab::fuse_mount::{FreezeDecision, LazySource, MountHandle, MutationGate, Overlay, spawn as spawn_mount},
    workspaces::lazy::Reader,
};
use std::{
    collections::HashMap,
    fs, io,
    os::fd::{FromRawFd, OwnedFd},
    os::unix::net::UnixStream,
    path::{Component, Path},
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{self, Receiver, SyncSender},
    },
    thread,
    time::{Duration, Instant},
};
use uuid::Uuid;

/// Per-mount operation queue, mirrored from `fuse_dispatch` for diagnostics.
const MOUNT_QUEUE_CAPACITY: u32 = 128;
const WATCHDOG_TICK: Duration = Duration::from_millis(100);

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

struct Mounted {
    handle: MountHandle,
    gate: Arc<MutationGate>,
    reader: Option<Arc<Reader>>,
}

struct FreezeOp {
    workspace: Uuid,
    epoch: i64,
    decision: SyncSender<bool>,
    /// Request id that must receive the `finished` reply once the gate is free.
    done: Arc<Mutex<Option<u64>>>,
}

struct State {
    generation: AtomicU64,
    hello: AtomicBool,
    last_heartbeat: Mutex<Instant>,
    control: Mutex<UnixStream>,
    mounts: Mutex<HashMap<Uuid, Mounted>>,
    freezes: Mutex<HashMap<u64, FreezeOp>>,
}

impl State {
    fn new(control: UnixStream) -> Self {
        Self {
            generation: AtomicU64::new(0),
            hello: AtomicBool::new(false),
            last_heartbeat: Mutex::new(Instant::now()),
            control: Mutex::new(control),
            mounts: Mutex::new(HashMap::new()),
            freezes: Mutex::new(HashMap::new()),
        }
    }

    fn fence_all(&self) {
        let gates: Vec<Arc<MutationGate>> = lock(&self.mounts).values().map(|m| m.gate.clone()).collect();
        for gate in gates {
            gate.fence();
        }
    }

    /// Dropping the senders makes every waiting freeze pick the fence branch.
    fn release_freezes(&self) {
        lock(&self.freezes).clear();
    }

    fn unmount_all(&self) {
        let mounts: Vec<Mounted> = lock(&self.mounts).drain().map(|(_, mount)| mount).collect();
        for mount in mounts {
            mount.handle.shutdown();
            drop(mount.handle);
        }
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
    let state = Arc::new(State::new(control));

    // A panic anywhere in the child must fence before anything else: the hook
    // runs before unwinding continues, so a half-finished operation can never
    // leave a writable mount behind. The control loop is additionally guarded
    // with `catch_unwind` below.
    let hook_state = state.clone();
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        hook_state.fence_all();
        hook_state.release_freezes();
        previous(info);
    }));

    let watchdog_state = state.clone();
    thread::Builder::new().name("fuse-helper-watchdog".into()).spawn(move || watchdog(watchdog_state))?;
    let heartbeat_state = state.clone();
    thread::Builder::new()
        .name("fuse-helper-heartbeat-reader".into())
        .spawn(move || heartbeat_reader(heartbeat_state, heartbeat))?;

    let loop_state = state.clone();
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| control_loop(loop_state, reader)));
    let reason = match outcome {
        Ok(Ok(())) => "control loop closed",
        Ok(Err(_)) => "control loop failed",
        Err(_) => "control loop panicked",
    };
    teardown(&state, reason, 1)
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

fn control_loop(state: Arc<State>, mut stream: UnixStream) -> io::Result<()> {
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
        if dispatch(&state, frame.request_id, frame.workspace, frame.db_epoch, body) {
            return Ok(());
        }
    }
}

/// Returns true when the child must stop serving.
fn dispatch(state: &Arc<State>, request: u64, workspace: Option<Uuid>, db_epoch: i64, body: Body) -> bool {
    match body {
        Body::Heartbeat(_) => {
            *lock(&state.last_heartbeat) = Instant::now();
        }
        Body::Mount(request_body) => mount(state, request, workspace, db_epoch, request_body),
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
        Body::FreezeBegin(FreezeBegin { op_id }) => freeze_begin(state, request, workspace, db_epoch, op_id),
        Body::FreezeFinish(FreezeFinish { op_id, epoch, thaw }) => {
            freeze_release(state, request, workspace, op_id, epoch, thaw)
        }
        Body::AbortFreeze(AbortFreeze { op_id }) => freeze_release(state, request, workspace, op_id, -1, false),
        Body::Prewarm(Prewarm { paths }) => prewarm(state, request, workspace, paths),
        Body::Unmount => {
            let removed = workspace.and_then(|ws| lock(&state.mounts).remove(&ws));
            match removed {
                Some(mount) => {
                    mount.handle.shutdown();
                    drop(mount);
                    reply(state, request, workspace, 0, Body::Unmounted);
                }
                None => reply_error(state, request, workspace, libc::ENOENT, "workspace is not mounted"),
            }
        }
        Body::Shutdown => {
            reply(state, request, None, 0, Body::ShuttingDown);
            state.fence_all();
            state.release_freezes();
            state.unmount_all();
            return true;
        }
        other => {
            reply_error(state, request, workspace, libc::EPROTO, format!("unexpected operation `{}`", other.op()));
        }
    }
    false
}

fn mount(state: &Arc<State>, request: u64, workspace: Option<Uuid>, db_epoch: i64, body: MountRequest) {
    let Some(claimed) = workspace else {
        return reply_error(state, request, None, libc::EINVAL, "mount requires a workspace id");
    };
    if claimed != body.workspace {
        return reply_error(state, request, workspace, libc::EINVAL, "workspace id mismatch");
    }
    if db_epoch <= 0 {
        return reply_error(state, request, workspace, libc::EINVAL, "mount requires a lease epoch");
    }
    if lock(&state.mounts).contains_key(&body.workspace) {
        return reply_error(state, request, workspace, libc::EEXIST, "workspace is already mounted");
    }
    let root = match validate_root(&body.root) {
        Ok(root) => root,
        Err(error) => return reply_errno(state, request, workspace, error),
    };
    let paths = workspace_paths(&root, body.workspace);
    if !paths.lower.join(".git").is_dir() {
        return reply_error(state, request, workspace, libc::ENOENT, "workspace lower Git state missing");
    }
    if let Err(error) = fs::create_dir_all(&paths.upper).and_then(|()| fs::create_dir_all(&paths.mountpoint)) {
        return reply_errno(state, request, workspace, error);
    }
    let gate = match MutationGate::new_with_lease(db_epoch, body.lease_until) {
        Ok(gate) => gate,
        Err(error) => return reply_errno(state, request, workspace, error),
    };
    let reader = if body.lazy {
        match Reader::open_root(&root, body.workspace) {
            Ok(reader) => reader,
            Err(_) => {
                return reply_error(
                    state,
                    request,
                    workspace,
                    libc::EIO,
                    "workspace lazy baseline is unavailable",
                );
            }
        }
    } else {
        None
    };
    let source: Option<Arc<dyn LazySource>> = reader.clone().map(|reader| reader as Arc<dyn LazySource>);
    let overlay = match Overlay::new_with_gate_and_lazy(paths.lower, paths.upper, gate.clone(), source) {
        Ok(overlay) => overlay,
        Err(error) => return reply_errno(state, request, workspace, error),
    };
    let handle = match spawn_mount(overlay, &paths.mountpoint) {
        Ok(handle) => handle,
        Err(error) => return reply_errno(state, request, workspace, error),
    };
    let epoch = gate.epoch();
    lock(&state.mounts).insert(body.workspace, Mounted { handle, gate, reader });
    reply(
        state,
        request,
        workspace,
        epoch,
        Body::Mounted(MountedReply { epoch, queue_capacity: MOUNT_QUEUE_CAPACITY }),
    );
}

fn freeze_begin(state: &Arc<State>, request: u64, workspace: Option<Uuid>, db_epoch: i64, op_id: u64) {
    let Some(ws) = workspace else {
        return reply_error(state, request, None, libc::EINVAL, "freeze requires a workspace id");
    };
    let Some(gate) = gate_for(state, ws) else {
        return reply_error(state, request, workspace, libc::ENOENT, "workspace is not mounted");
    };
    if db_epoch != gate.epoch() {
        return reply_error(state, request, workspace, libc::ESTALE, "freeze epoch is not the mounted epoch");
    }
    {
        let freezes = lock(&state.freezes);
        if freezes.values().any(|op| op.workspace == ws) {
            return reply_error(state, request, workspace, libc::EBUSY, "workspace already has a freeze operation");
        }
        if freezes.contains_key(&op_id) {
            return reply_error(state, request, workspace, libc::EEXIST, "freeze operation id reused");
        }
    }
    let (decision, waiter) = mpsc::sync_channel::<bool>(1);
    let done = Arc::new(Mutex::new(None::<u64>));
    lock(&state.freezes).insert(op_id, FreezeOp { workspace: ws, epoch: db_epoch, decision, done: done.clone() });
    let thread_state = state.clone();
    let spawned = thread::Builder::new().name(format!("fuse-helper-freeze-{op_id}")).spawn(move || {
        freeze_thread(thread_state, ws, op_id, db_epoch, gate, request, waiter, done)
    });
    if let Err(error) = spawned {
        lock(&state.freezes).remove(&op_id);
        reply_error(state, request, workspace, libc::EAGAIN, format!("cannot start freeze thread: {error}"));
    }
}

fn freeze_thread(
    state: Arc<State>,
    workspace: Uuid,
    op_id: u64,
    epoch: i64,
    gate: Arc<MutationGate>,
    begin_request: u64,
    waiter: Receiver<bool>,
    done: Arc<Mutex<Option<u64>>>,
) {
    // The acknowledgement is sent by this thread once the gate really drained;
    // the control loop keeps serving other mounts while it waits.
    let _ = gate.freeze_with_decision(|| {
        reply(
            &state,
            begin_request,
            Some(workspace),
            epoch,
            Body::Ok(OkReply { op_id: Some(op_id) }),
        );
        let thaw = waiter.recv().unwrap_or(false);
        let decision = if thaw { FreezeDecision::Thaw } else { FreezeDecision::Fence };
        ((), decision)
    });
    let finished = { let mut slot = lock(&done); slot.take() };
    if let Some(request) = finished {
        reply(
            &state,
            request,
            Some(workspace),
            epoch,
            Body::Ok(OkReply { op_id: Some(op_id) }),
        );
    }
}

/// One-shot finish/abort. `epoch < 0` skips the epoch comparison for an abort.
fn freeze_release(
    state: &Arc<State>,
    request: u64,
    workspace: Option<Uuid>,
    op_id: u64,
    epoch: i64,
    thaw: bool,
) {
    let op = lock(&state.freezes).remove(&op_id);
    let Some(op) = op else {
        return reply_error(state, request, workspace, libc::ESTALE, "freeze operation is not pending");
    };
    if epoch >= 0 && epoch != op.epoch {
        // Put it back: a mismatched epoch must not consume the one-shot.
        lock(&state.freezes).insert(op_id, op);
        return reply_error(state, request, workspace, libc::ESTALE, "freeze epoch mismatch");
    }
    *lock(&op.done) = Some(request);
    if op.decision.send(thaw).is_err() {
        reply_error(state, request, workspace, libc::ESRCH, "freeze thread is gone; the epoch stays fenced");
    }
}

fn prewarm(state: &Arc<State>, request: u64, workspace: Option<Uuid>, paths: Vec<String>) {
    let Some(ws) = workspace else {
        return reply_error(state, request, None, libc::EINVAL, "prewarm requires a workspace id");
    };
    if paths.len() > 4 {
        return reply_error(state, request, workspace, libc::EINVAL, "prewarm accepts at most four paths");
    }
    let relative: Vec<std::path::PathBuf> = match paths.iter().map(|path| relative_path(path)).collect() {
        Ok(paths) => paths,
        Err(error) => return reply_errno(state, request, workspace, error),
    };
    let reader = match lock(&state.mounts).get(&ws).and_then(|mount| mount.reader.clone()) {
        Some(reader) => reader,
        None => return reply_error(state, request, workspace, libc::ENOENT, "workspace has no lazily hydrated baseline"),
    };
    let thread_state = state.clone();
    let spawned = thread::Builder::new().name("fuse-helper-prewarm".into()).spawn(move || {
        match reader.prewarm(&relative) {
            Ok((files, bytes)) => reply(
                &thread_state,
                request,
                Some(ws),
                0,
                Body::Prewarmed(PrewarmReply { files, bytes }),
            ),
            Err(error) => {
                let code = error.raw_os_error().unwrap_or(libc::EIO);
                reply_error(&thread_state, request, Some(ws), code, error.to_string());
            }
        }
    });
    if let Err(error) = spawned {
        reply_error(state, request, workspace, libc::EAGAIN, format!("cannot start prewarm thread: {error}"));
    }
}

/// Prewarm paths are caller-relative: no absolute path and no parent traversal.
fn relative_path(raw: &str) -> io::Result<std::path::PathBuf> {
    let path = Path::new(raw);
    if path.is_absolute() && !raw.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "prewarm path must be relative"));
    }
    if !path.components().all(|part| matches!(part, Component::Normal(_) | Component::CurDir)) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "prewarm path escapes the workspace"));
    }
    Ok(path.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prewarm_paths_must_stay_inside_the_workspace() {
        assert!(relative_path("src/main.rs").is_ok());
        assert!(relative_path("./a").is_ok());
        assert!(relative_path("/etc/shadow").is_err());
        assert!(relative_path("../escape").is_err());
        assert!(relative_path("a/../../b").is_err());
    }

    #[test]
    fn teardown_policy_can_only_fence() {
        // A dropped freeze waiter is a fence: the receiver sees `Err` and the
        // freeze thread applies `FreezeDecision::Fence`.
        let (sender, receiver) = mpsc::sync_channel::<bool>(1);
        drop(sender);
        assert!(receiver.recv().is_err());
    }
}
