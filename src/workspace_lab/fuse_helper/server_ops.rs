//! Blocking child operations: mount, unmount, freeze and prewarm.
//!
//! Everything here runs on a bounded worker pool (or a dedicated freeze
//! thread), never on the control reader. Locks are only held for map updates,
//! never across a filesystem walk, a session join or an RPC write, and every
//! operation has an independent deadline so a caller that disappeared cannot
//! park a gate or a per-workspace slot forever.
use super::super::protocol::{
    Body, FREEZE_OP_DEADLINE, MOUNT_OP_DEADLINE, MountRequest, MountedReply, OkReply, PREWARM_DEADLINE, PrewarmReply,
};
use super::{
    FreezeOp, MOUNT_QUEUE_CAPACITY, Mounted, PendingMount, State, TOMBSTONES, gate_for, lock, reply, reply_error,
    reply_errno,
};
use crate::workspace_lab::fuse_helper::{validate_root, workspace_paths};
use crate::workspace_lab::fuse_mount::{FreezeDecision, LazySource, MutationGate, Overlay, spawn as spawn_mount};
use crate::workspaces::lazy::Reader;
use std::{
    fs, io,
    path::{Component, Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver},
    },
    thread,
    time::Instant,
};
use uuid::Uuid;

/// Re-check cancellation and the operation deadline at every checkpoint. A
/// mount that passes the deadline or was cancelled must never be published.
pub(super) fn checkpoint(cancel: &AtomicBool, deadline: Instant) -> Result<(), (i32, String)> {
    if cancel.load(Ordering::Acquire) {
        return Err((libc::ECANCELED, "operation was cancelled".into()));
    }
    if Instant::now() >= deadline {
        return Err((libc::ETIMEDOUT, "operation deadline expired".into()));
    }
    Ok(())
}

pub(super) fn push_freeze_tombstone(state: &State, op_id: u64) {
    let mut tombstones = lock(&state.freeze_tombstones);
    if tombstones.len() >= TOMBSTONES {
        tombstones.pop_front();
    }
    tombstones.push_back(op_id);
}

pub(super) fn take_freeze_tombstone(state: &State, op_id: u64) -> bool {
    let mut tombstones = lock(&state.freeze_tombstones);
    match tombstones.iter().position(|candidate| *candidate == op_id) {
        Some(index) => {
            tombstones.remove(index);
            true
        }
        None => false,
    }
}

pub(super) fn push_mount_tombstone(state: &State, workspace: Uuid, request: u64) {
    let mut tombstones = lock(&state.mount_tombstones);
    if tombstones.len() >= TOMBSTONES {
        tombstones.pop_front();
    }
    tombstones.push_back((workspace, request));
}

fn take_mount_tombstone(state: &State, workspace: Uuid, request: u64) -> bool {
    let mut tombstones = lock(&state.mount_tombstones);
    match tombstones.iter().position(|candidate| *candidate == (workspace, request)) {
        Some(index) => {
            tombstones.remove(index);
            true
        }
        None => false,
    }
}

/// Linearize admission with `cancel_mount`: the tombstone check, the busy
/// check and the pending insert share one `pending` guard, so an abort cannot
/// fall between the check and the registration.
pub(super) fn register_pending(
    state: &State,
    workspace: Uuid,
    request: u64,
    deadline: Instant,
    cancel: Arc<AtomicBool>,
) -> Result<(), (i32, String)> {
    let mut pending = lock(&state.pending);
    if let Some(entry) = pending.get(&workspace) {
        if entry.cancelled.load(Ordering::Acquire) || Instant::now() >= entry.deadline {
            return Err((libc::ETIMEDOUT, "the previous operation on this workspace timed out".into()));
        }
        return Err((libc::EBUSY, "another mount or unmount owns this workspace".into()));
    }
    if take_mount_tombstone(state, workspace, request) {
        return Err((libc::ECANCELED, "mount was cancelled before it was admitted".into()));
    }
    pending.insert(workspace, PendingMount { request, deadline, cancelled: cancel, gate: None });
    Ok(())
}

fn remove_pending(state: &State, workspace: Uuid, request: u64) {
    let mut pending = lock(&state.pending);
    if pending.get(&workspace).map(|entry| entry.request) == Some(request) {
        pending.remove(&workspace);
    }
}

pub(super) fn mount(
    state: &Arc<State>,
    request: u64,
    workspace: Option<Uuid>,
    db_epoch: i64,
    body: MountRequest,
) {
    let Some(claimed) = workspace else {
        return reply_error(state, request, None, libc::EINVAL, "mount requires a workspace id");
    };
    if claimed != body.workspace {
        return reply_error(state, request, workspace, libc::EINVAL, "workspace id mismatch");
    }
    if db_epoch <= 0 {
        return reply_error(state, request, workspace, libc::EINVAL, "mount requires a lease epoch");
    }
    // Idempotent retry: a mount whose reply was lost may already be published
    // at exactly this epoch and root. Reuse it instead of failing with EEXIST
    // forever; anything else must be reconciled explicitly.
    let existing = lock(&state.mounts)
        .get(&body.workspace)
        .map(|mount| (mount.gate.epoch(), mount.root.clone()));
    if let Some((epoch, root)) = existing {
        let same_root = root == Path::new(&body.root)
            || validate_root(&body.root).map(|candidate| candidate == root).unwrap_or(false);
        if same_root && epoch == db_epoch {
            // The retry now owns the registration: a delayed cancel for the
            // previous frame must not remove the mount this retry just reused.
            if let Some(mount) = lock(&state.mounts).get_mut(&body.workspace) {
                mount.request = request;
            }
            return reply(
                state,
                request,
                workspace,
                epoch,
                Body::Mounted(MountedReply { epoch, queue_capacity: MOUNT_QUEUE_CAPACITY }),
            );
        }
        return reply_error(
            state,
            request,
            workspace,
            libc::EEXIST,
            "workspace is already mounted at another epoch or root; reconcile the lease first",
        );
    }
    let cancel = Arc::new(AtomicBool::new(false));
    let deadline = Instant::now() + MOUNT_OP_DEADLINE;
    if let Err((code, message)) = register_pending(state, body.workspace, request, deadline, cancel.clone()) {
        return reply_error(state, request, workspace, code, message);
    }
    match build(state, &body, db_epoch, &cancel, deadline) {
        Ok((handle, gate, reader, root)) => publish(state, request, workspace, body.workspace, handle, gate, reader, root),
        Err((code, message)) => {
            remove_pending(state, body.workspace, request);
            reply_error(state, request, workspace, code, message);
        }
    }
}

type Built = (crate::workspace_lab::fuse_mount::MountHandle, Arc<MutationGate>, Option<Arc<Reader>>, PathBuf);

fn build(
    state: &State,
    body: &MountRequest,
    db_epoch: i64,
    cancel: &AtomicBool,
    deadline: Instant,
) -> Result<Built, (i32, String)> {
    let root = validate_root(&body.root).map_err(|error| {
        (error.raw_os_error().unwrap_or(libc::EINVAL), format!("helper root rejected: {error}"))
    })?;
    let paths = workspace_paths(&root, body.workspace);
    if !paths.lower.join(".git").is_dir() {
        return Err((libc::ENOENT, "workspace lower Git state missing".into()));
    }
    checkpoint(cancel, deadline)?;
    fs::create_dir_all(&paths.upper)
        .and_then(|()| fs::create_dir_all(&paths.mountpoint))
        .map_err(|error| (error.raw_os_error().unwrap_or(libc::EIO), error.to_string()))?;
    let gate = MutationGate::new_with_lease(db_epoch, body.lease_until)
        .map_err(|error| (error.raw_os_error().unwrap_or(libc::EINVAL), error.to_string()))?;
    // Register the gate before the slow work: the watchdog can fence a mount
    // that is still being built, and a watcher never sees an unfenced pending
    // mount as mounted.
    lock(&state.pending).get_mut(&body.workspace).map(|entry| entry.gate = Some(gate.clone()));
    checkpoint(cancel, deadline)?;
    let reader = if body.lazy {
        match Reader::open_root(&root, body.workspace) {
            Ok(reader) => Some(reader),
            Err(_) => return Err((libc::EIO, "workspace lazy baseline is unavailable".into())),
        }
    } else {
        None
    };
    checkpoint(cancel, deadline)?;
    let source: Option<Arc<dyn LazySource>> = reader.clone().map(|reader| reader as Arc<dyn LazySource>);
    let overlay = Overlay::new_with_gate_and_lazy(paths.lower, paths.upper, gate.clone(), source)
        .map_err(|error| (error.raw_os_error().unwrap_or(libc::EIO), error.to_string()))?;
    checkpoint(cancel, deadline)?;
    let handle = spawn_mount(overlay, &paths.mountpoint)
        .map_err(|error| (error.raw_os_error().unwrap_or(libc::EIO), error.to_string()))?;
    Ok((handle, gate, reader, root))
}

#[allow(clippy::too_many_arguments)]
fn publish(
    state: &Arc<State>,
    request: u64,
    workspace: Option<Uuid>,
    ws: Uuid,
    handle: crate::workspace_lab::fuse_mount::MountHandle,
    gate: Arc<MutationGate>,
    reader: Option<Arc<Reader>>,
    root: PathBuf,
) {
    // Publish and the cancel path share the pending lock: a cancel either
    // marks the pending entry first (and this publish refuses) or finds the
    // published mount afterwards (and tears it down). No window publishes a
    // mount the parent already gave up on.
    let mut pending = lock(&state.pending);
    let Some(entry) = pending.get(&ws) else {
        drop(pending);
        handle.shutdown();
        drop(handle);
        return reply_error(state, request, workspace, libc::ESTALE, "mount was cancelled before it was published");
    };
    let cancelled = entry.cancelled.load(Ordering::Acquire);
    let expired = Instant::now() >= entry.deadline;
    let owned = entry.request == request;
    if !owned || cancelled || expired {
        pending.remove(&ws);
        drop(pending);
        handle.shutdown();
        drop(handle);
        let (code, message) = if cancelled {
            (libc::ECANCELED, "mount was cancelled before it was published")
        } else if expired {
            (libc::ETIMEDOUT, "mount deadline expired before it was published")
        } else {
            (libc::ESTALE, "mount was superseded before it was published")
        };
        return reply_error(state, request, workspace, code, message);
    }
    let epoch = gate.epoch();
    {
        let mut mounts = lock(&state.mounts);
        if mounts.contains_key(&ws) {
            drop(mounts);
            pending.remove(&ws);
            drop(pending);
            handle.shutdown();
            drop(handle);
            return reply_error(state, request, workspace, libc::EEXIST, "workspace is already mounted");
        }
        mounts.insert(ws, Mounted { handle, gate, reader, root, request });
    }
    pending.remove(&ws);
    drop(pending);
    reply(
        state,
        request,
        workspace,
        epoch,
        Body::Mounted(MountedReply { epoch, queue_capacity: MOUNT_QUEUE_CAPACITY }),
    );
}

/// Cancel one admitted mount and remove a mount that was published after the
/// reply was lost. Returns the published mount so a worker can join it.
pub(super) fn cancel_mount(state: &Arc<State>, workspace: Option<Uuid>, mount_request: u64) -> Option<Mounted> {
    let ws = workspace?;
    // Registration and this cancel share the `pending` guard: either the
    // pending entry exists here, or it can no longer be admitted. The tombstone
    // is stored under the same guard so a mount that has not reached
    // `register_pending` yet is refused when it does.
    let pending_gate = {
        let mut pending = lock(&state.pending);
        push_mount_tombstone(state, ws, mount_request);
        match pending.get_mut(&ws) {
            Some(entry) if entry.request == mount_request => {
                entry.cancelled.store(true, Ordering::Release);
                entry.gate.clone()
            }
            _ => None,
        }
    };
    // Fence synchronously, before the slow session join is queued: a cancelling
    // mount must stop admitting mutations even while its handle still exists.
    if let Some(gate) = pending_gate {
        gate.fence();
    }
    let mut mounts = lock(&state.mounts);
    match mounts.get(&ws) {
        Some(mount) if mount.request == mount_request => {
            mount.gate.fence();
            mounts.remove(&ws)
        }
        _ => None,
    }
}

pub(super) fn abort_mount_reply(
    state: &Arc<State>,
    request: u64,
    workspace: Option<Uuid>,
    removed: Option<Mounted>,
) {
    if let Some(mount) = removed {
        mount.handle.shutdown();
        drop(mount.handle);
    }
    reply(state, request, workspace, 0, Body::Ok(OkReply { op_id: None }));
}

pub(super) fn unmount(state: &Arc<State>, request: u64, workspace: Option<Uuid>) {
    let Some(ws) = workspace else {
        return reply_error(state, request, None, libc::EINVAL, "unmount requires a workspace id");
    };
    // Take the pending entry first: a mount still building can no longer
    // publish once its pending entry is gone, and its own deadline cleans it.
    lock(&state.pending).remove(&ws);
    let removed = lock(&state.mounts).remove(&ws);
    match removed {
        Some(mount) => {
            mount.handle.shutdown();
            drop(mount);
            reply(state, request, workspace, 0, Body::Unmounted);
        }
        None => reply_error(state, request, workspace, libc::ENOENT, "workspace is not mounted"),
    }
}

pub(super) fn freeze_begin(state: &Arc<State>, request: u64, workspace: Option<Uuid>, db_epoch: i64, op_id: u64) {
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
    if take_freeze_tombstone(state, op_id) {
        return reply_error(state, request, workspace, libc::ESTALE, "freeze operation was already cancelled");
    }
    let (decision, waiter) = mpsc::sync_channel::<bool>(1);
    let done = Arc::new(Mutex::new(None::<u64>));
    let deadline = Instant::now() + FREEZE_OP_DEADLINE;
    lock(&state.freezes).insert(
        op_id,
        FreezeOp {
            workspace: ws,
            epoch: db_epoch,
            begin_request: request,
            deadline,
            failstop_at: deadline + super::FREEZE_JOIN_GRACE,
            expired: AtomicBool::new(false),
            decision,
            done: done.clone(),
            released: AtomicBool::new(false),
        },
    );
    let thread_state = state.clone();
    let spawned = thread::Builder::new().name(format!("fuse-helper-freeze-{op_id}")).spawn(move || {
        freeze_thread(thread_state, ws, op_id, db_epoch, gate, request, deadline, waiter, done)
    });
    if let Err(error) = spawned {
        take_freeze_op(state, op_id, request);
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
    deadline: Instant,
    waiter: Receiver<bool>,
    done: Arc<Mutex<Option<u64>>>,
) {
    // The acknowledgement is sent once the gate really drained; the control
    // loop keeps serving other mounts while this thread waits. The wait has an
    // independent deadline: a begin whose caller vanished releases the gate as
    // a fence instead of holding it (and the per-mount slot) forever.
    let drained = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = gate.freeze_with_decision(|| {
            reply(&state, begin_request, Some(workspace), epoch, Body::Ok(OkReply { op_id: Some(op_id) }));
            let wait = deadline.saturating_duration_since(Instant::now());
            let thaw = match waiter.recv_timeout(wait) {
                Ok(thaw) => thaw,
                // Timeout or a dropped sender: a fence, never a thaw.
                Err(_) => false,
            };
            ((), if thaw { FreezeDecision::Thaw } else { FreezeDecision::Fence })
        });
    }));
    if drained.is_err() {
        // A panicking worker must fail the whole helper, not keep serving with
        // a gate that only looks fenced.
        super::failstop(&state, "freeze worker panicked", 1);
    }
    // Remove this op only if it is still the same one, even when a late
    // finish/abort raced the deadline. That keeps the next freeze from failing
    // with EBUSY against a stale map entry.
    if let Some(op) = take_freeze_op(&state, op_id, begin_request) {
        let finished = { lock(&op.done).take() };
        if let Some(finish_request) = finished {
            reply(&state, finish_request, Some(workspace), epoch, Body::Ok(OkReply { op_id: Some(op_id) }));
        }
    }
}

fn take_freeze_op(state: &State, op_id: u64, begin_request: u64) -> Option<FreezeOp> {
    let mut freezes = lock(&state.freezes);
    match freezes.get(&op_id) {
        Some(op) if op.begin_request == begin_request => freezes.remove(&op_id),
        _ => None,
    }
}

/// One-shot finish/abort.
///
/// `frame_epoch` is the envelope `db_epoch` of the finish/abort frame: it must
/// name this operation's epoch, so a frame for another epoch/workspace cannot
/// release a freeze it does not own. `epoch < 0` marks an abort, which still
/// names the same workspace and fences the gate before releasing the thread.
/// An accepted release records the actual finish request in `done`; the freeze
/// thread replies with that id and the operation epoch once the decision has
/// been applied, so `finish` never waits for an acknowledgement nobody sends.
pub(super) fn freeze_release(
    state: &Arc<State>,
    request: u64,
    workspace: Option<Uuid>,
    op_id: u64,
    frame_epoch: i64,
    epoch: i64,
    thaw: bool,
) {
    let (claimed, exists) = {
        let freezes = lock(&state.freezes);
        match freezes.get(&op_id) {
            Some(op) if workspace == Some(op.workspace) && frame_epoch == op.epoch => {
                if epoch >= 0 && epoch != op.epoch {
                    (Err((libc::ESTALE, "freeze epoch does not match the operation")), true)
                } else if op.released.swap(true, Ordering::AcqRel) {
                    (Err((libc::ESTALE, "freeze operation was already released")), true)
                } else {
                    let mut done = lock(&op.done);
                    if done.is_some() {
                        (Err((libc::ESTALE, "freeze operation already has a finishing request")), true)
                    } else {
                        *done = Some(request);
                        (Ok(op.workspace), true)
                    }
                }
            }
            Some(_) => (Err((libc::ESTALE, "freeze frame does not match the operation context")), true),
            None => (Err((libc::ESTALE, "freeze operation is not pending")), false),
        }
    };
    let op_workspace = match claimed {
        Ok(workspace) => workspace,
        Err((code, message)) => {
            if epoch < 0 && !exists {
                // Idempotent cancel of a freeze that never registered:
                // remember the op so a late begin cannot revive it.
                push_freeze_tombstone(state, op_id);
                return reply(state, request, workspace, frame_epoch, Body::Ok(OkReply { op_id: Some(op_id) }));
            }
            return reply_error(state, request, workspace, code, message);
        }
    };
    if epoch < 0 {
        if let Some(gate) = gate_for(state, op_workspace) {
            gate.fence();
        }
    }
    let sent = {
        let freezes = lock(&state.freezes);
        freezes.get(&op_id).map(|op| op.decision.send(thaw).is_ok()).unwrap_or(false)
    };
    if !sent {
        // The decision could not be delivered (the thread is gone or the
        // watchdog already queued a fence). Drop our acknowledgement claim so
        // no stale `finished` reply can claim the decision was applied.
        let mut done = { let freezes = lock(&state.freezes); freezes.get(&op_id).map(|op| op.done.clone()) };
        if let Some(slot) = done.as_mut() {
            let mut slot = lock(&**slot);
            if *slot == Some(request) {
                *slot = None;
            }
        }
        reply_error(state, request, workspace, libc::ESRCH, "freeze thread is gone; the epoch stays fenced");
    }
}

pub(super) fn prewarm(state: &Arc<State>, request: u64, workspace: Option<Uuid>, paths: Vec<String>) {
    let Some(ws) = workspace else {
        return reply_error(state, request, None, libc::EINVAL, "prewarm requires a workspace id");
    };
    if paths.len() > 4 {
        return reply_error(state, request, workspace, libc::EINVAL, "prewarm accepts at most four paths");
    }
    // One deadline for the whole request: queued work plus hydration shares
    // the caller's 60s budget instead of multiplying it per path.
    let deadline = Instant::now() + PREWARM_DEADLINE;
    let relative: Vec<PathBuf> = match paths.iter().map(|path| relative_path(path)).collect() {
        Ok(paths) => paths,
        Err(error) => return reply_errno(state, request, workspace, error),
    };
    let reader = match lock(&state.mounts).get(&ws).and_then(|mount| mount.reader.clone()) {
        Some(reader) => reader,
        None => {
            return reply_error(state, request, workspace, libc::ENOENT, "workspace has no lazily hydrated baseline")
        }
    };
    if Instant::now() >= deadline {
        return reply_error(state, request, workspace, libc::ETIMEDOUT, "prewarm deadline expired before it started");
    }
    match reader.prewarm(&relative) {
        Ok((files, bytes)) => reply(
            state,
            request,
            workspace,
            0,
            Body::Prewarmed(PrewarmReply { files: files as u64, bytes }),
        ),
        Err(error) => {
            let code = error.raw_os_error().unwrap_or(libc::EIO);
            reply_error(state, request, workspace, code, error.to_string());
        }
    }
}

/// Prewarm paths are caller-relative: no absolute path and no parent traversal.
fn relative_path(raw: &str) -> io::Result<PathBuf> {
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
    use std::time::Duration;

    #[test]
    fn prewarm_paths_must_stay_inside_the_workspace() {
        assert!(relative_path("src/main.rs").is_ok());
        assert!(relative_path("./a").is_ok());
        assert!(relative_path("/etc/shadow").is_err());
        assert!(relative_path("../escape").is_err());
        assert!(relative_path("a/../../b").is_err());
    }

    #[test]
    fn cancelled_or_expired_work_is_never_completed() {
        assert_eq!(checkpoint(&AtomicBool::new(true), Instant::now() + Duration::from_secs(30)).unwrap_err().0, libc::ECANCELED);
        assert_eq!(checkpoint(&AtomicBool::new(false), Instant::now()).unwrap_err().0, libc::ETIMEDOUT);
        assert!(checkpoint(&AtomicBool::new(false), Instant::now() + Duration::from_secs(30)).is_ok());
    }
}
