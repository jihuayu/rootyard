//! Bounded per-mount dispatch: one actor owns the overlay and the mutation gate.
//!
//! The kernel-facing shim runs on the FUSE session thread. It never touches the
//! overlay, never admits a mutation and never waits: it copies the request into
//! an [`OwnedOp`] and `try_send`s it to this mount's queue. One actor thread per
//! mount owns [`Overlay`] and is the only caller of [`MutationGate::mutation`],
//! so exactly one admission covers one mutation and no thread-local
//! `MutationGuard` is ever moved across threads.
//!
//! Freeze policy:
//!
//! * `Frozen`: mutations (write/create/setattr/mkdir/unlink/rmdir/rename and
//!   write-flagged open) are parked in a bounded FIFO and their replies are held;
//!   reads, lookup, readlink, readdir and read-only open keep executing.
//! * `Healthy` after a thaw: the FIFO is drained in order. The actor notices the
//!   thaw by bounded `recv_timeout` polling (10 ms), never by requiring a new
//!   kernel request, and notifies itself on enqueue.
//! * `Fenced`: parked mutations reply `EROFS`; new mutations are rejected with
//!   `EROFS` as well and reads continue.
//! * Only queue saturation (per-mount 128 ops / 8 MiB, all mounts together
//!   1024 ops / 32 MiB) replies `EAGAIN`; a normal freeze parks writes until the
//!   thaw succeeds.
//!
//! A queued mutation is bound to the lease epoch that was authorized when the
//! shim enqueued it. The actor admits the mutation once and compares the guard's
//! epoch with that stamp; a mismatch (the gate moved to a newer lease while the
//! operation was parked) drops the guard and replies `EROFS` without running the
//! operation. This closes the window where a 10 ms actor poll misses a transient
//! `Fenced` phase and observes only the new `Healthy` epoch.
//!
//! Every queued operation holds an RAII [`Permit`] charged against both budgets
//! until its reply is sent, so queued bytes and delayed read replies are counted,
//! not only the frozen FIFO. Delayed lazy reads are handed to the global read
//! pool (4 workers, 256 jobs); saturation replies `EAGAIN` instead of doing the
//! read inline on the actor. Each deferred job owns and sends exactly one reply.
//! Shutdown drains every reply still sitting in a queue slot; a read already
//! executing in the pool checks the shutdown flag after its I/O and replies
//! `EIO` instead of a late success. Joining that in-flight read is still a
//! helper-phase responsibility, not something this dispatch loop can prove.
use super::inner_ops::{ReadPlan, read_at};
use super::owned_ops::OwnedOp;
use super::*;
use budget::{Budget, Permit, global_budget};
use fuser::ReplyData;
use read_pool::{ReadJob, ReadPool, global as global_read_pool};
use std::collections::VecDeque;
use std::sync::{
    Condvar, Mutex, MutexGuard, PoisonError,
    atomic::{AtomicUsize, Ordering},
};

#[path = "fuse_dispatch/budget.rs"]
mod budget;
#[path = "fuse_dispatch/read_pool.rs"]
mod read_pool;

pub const MOUNT_QUEUE_OPS: usize = 128;
pub const MOUNT_QUEUE_BYTES: usize = 8 * 1024 * 1024;
const GLOBAL_QUEUE_OPS: usize = 1024;
const GLOBAL_QUEUE_BYTES: usize = 32 * 1024 * 1024;
/// Upper bound on how long the actor waits before re-checking the gate phase.
pub const ACTOR_POLL: Duration = Duration::from_millis(10);

/// Exact queue accounting exposed for tests and diagnostics.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QueueUsage {
    pub mount_ops: usize,
    pub mount_bytes: usize,
    pub global_ops: usize,
    pub global_bytes: usize,
    pub ready: usize,
    pub frozen: usize,
    pub pending_reads: usize,
    /// Actor-observed `Fenced` phases. Incremented only where the actor itself
    /// reads the phase, never by `MutationGate::fence`, so a zero delta means
    /// the actor's bounded poll skipped a transient fence. Fixed cardinality:
    /// no user identity, request identity or metric label.
    pub fence_observations: usize,
    /// Parked mutations dropped because their enqueue epoch did not match the
    /// epoch of the admitted guard (a handoff raced the queued operation).
    pub epoch_mismatch_rejections: usize,
}

/// Why the shim could not enqueue. Saturation is the only `EAGAIN`; a closed
/// queue after shutdown replies `EIO`.
pub(super) enum Reject {
    Saturated(OwnedOp),
    Closed(OwnedOp),
}

struct Queued {
    op: OwnedOp,
    /// Lease epoch observed at enqueue time for a mutation. `None` for reads and
    /// for any path that failed to stamp; a mutation with no stamp fails closed.
    epoch: Option<i64>,
    _permit: Permit,
}

/// Ready/frozen work with shutdown admission kept inside one lock.
///
/// The executor uses the non-draining pops, which refuse to pop after
/// [`WorkQueue::close`]. Shutdown cleanup uses the explicit drain pops so queued
/// replies are still removed and failed instead of being leaked.
struct WorkQueue<T> {
    ready: VecDeque<T>,
    frozen: VecDeque<T>,
    shutdown: bool,
}

impl<T> WorkQueue<T> {
    fn new() -> Self {
        Self { ready: VecDeque::new(), frozen: VecDeque::new(), shutdown: false }
    }

    /// `None` on success, `Some(item)` once the queue is closed.
    fn push_ready(&mut self, item: T) -> Option<T> {
        if self.shutdown {
            return Some(item);
        }
        self.ready.push_back(item);
        None
    }

    fn push_frozen_back(&mut self, item: T) {
        self.frozen.push_back(item);
    }

    fn pop_ready(&mut self) -> Option<T> {
        if self.shutdown {
            return None;
        }
        self.ready.pop_front()
    }

    fn pop_frozen(&mut self) -> Option<T> {
        if self.shutdown {
            return None;
        }
        self.frozen.pop_front()
    }

    fn pop_ready_for_drain(&mut self) -> Option<T> {
        self.ready.pop_front()
    }

    fn pop_frozen_for_drain(&mut self) -> Option<T> {
        self.frozen.pop_front()
    }

    fn close(&mut self) {
        self.shutdown = true;
    }

    fn is_shutdown(&self) -> bool {
        self.shutdown
    }

    fn lens(&self) -> (usize, usize) {
        (self.ready.len(), self.frozen.len())
    }
}

struct Shared {
    state: Mutex<WorkQueue<Queued>>,
    wake: Condvar,
    /// Deferred lazy reads that have not completed. A slot may already be empty
    /// when its pool worker is doing I/O; shutdown cannot answer that read, but
    /// the worker re-checks the shutdown flag before replying.
    deferred: Mutex<Vec<(u64, Arc<Mutex<Option<DeferredRead>>>)>>,
    next_deferred: AtomicUsize,
    /// Fixed-cardinality actor diagnostics; see [`QueueUsage`].
    fence_observations: AtomicUsize,
    epoch_mismatch_rejections: AtomicUsize,
}

impl Shared {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(WorkQueue::new()),
            wake: Condvar::new(),
            deferred: Mutex::new(Vec::new()),
            next_deferred: AtomicUsize::new(0),
            fence_observations: AtomicUsize::new(0),
            epoch_mismatch_rejections: AtomicUsize::new(0),
        })
    }

    fn lock(&self) -> MutexGuard<'_, WorkQueue<Queued>> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn observe_fenced(&self) {
        self.fence_observations.fetch_add(1, Ordering::Relaxed);
    }

    fn reject_epoch_mismatch(&self) {
        self.epoch_mismatch_rejections.fetch_add(1, Ordering::Relaxed);
    }

    fn diagnostics(&self) -> (usize, usize) {
        (self.fence_observations.load(Ordering::Relaxed), self.epoch_mismatch_rejections.load(Ordering::Relaxed))
    }

    fn push_ready(&self, queued: Queued) -> Option<Queued> {
        let mut state = self.lock();
        let rejected = state.push_ready(queued);
        drop(state);
        if rejected.is_none() {
            self.wake.notify_all();
        }
        rejected
    }

    fn push_frozen_back(&self, queued: Queued) {
        self.lock().push_frozen_back(queued);
        self.wake.notify_all();
    }

    fn take_frozen_front(&self) -> Option<Queued> {
        self.lock().pop_frozen()
    }

    fn pop_ready_timeout(&self, timeout: Duration) -> Option<Queued> {
        let mut state = self.lock();
        if state.is_shutdown() {
            return None;
        }
        if state.ready.is_empty() {
            let (next, _) = self.wake.wait_timeout(state, timeout).unwrap_or_else(PoisonError::into_inner);
            state = next;
        }
        state.pop_ready()
    }

    fn is_shutdown(&self) -> bool {
        self.lock().is_shutdown()
    }

    fn close(&self) {
        self.lock().close();
        self.wake.notify_all();
    }

    fn lens(&self) -> (usize, usize) {
        self.lock().lens()
    }

    fn register_deferred(&self, slot: Arc<Mutex<Option<DeferredRead>>>) -> u64 {
        let id = self.next_deferred.fetch_add(1, Ordering::Relaxed) as u64;
        self.deferred.lock().unwrap_or_else(PoisonError::into_inner).push((id, slot));
        id
    }

    fn complete_deferred(&self, id: u64) {
        self.deferred.lock().unwrap_or_else(PoisonError::into_inner).retain(|(candidate, _)| *candidate != id);
    }

    /// Number of deferred reads that still have a registered slot, including a
    /// worker currently executing I/O outside the slot lock.
    fn pending_deferred(&self) -> usize {
        self.deferred.lock().unwrap_or_else(PoisonError::into_inner).len()
    }

    /// Reply to every deferred read whose reply is still in its slot with one
    /// errno. A worker that already took the slot is doing I/O and re-checks the
    /// shutdown flag itself; it sends the one reply for that read. This never
    /// holds a slot lock across I/O, so a slow lower source cannot block the
    /// control plane.
    fn drain_deferred(&self, errno: i32) {
        let entries = std::mem::take(&mut *self.deferred.lock().unwrap_or_else(PoisonError::into_inner));
        for (_, slot) in entries {
            if let Some(deferred) = slot.lock().unwrap_or_else(PoisonError::into_inner).take() {
                deferred.reject(errno);
            }
        }
    }
}

/// A lazy read whose reply and budget charge travel to the read pool together.
struct DeferredRead {
    relative: PathBuf,
    source: Entry,
    lazy: Arc<dyn LazySource>,
    offset: i64,
    size: u32,
    reply: Option<ReplyData>,
    /// RAII queue budget for the read reply; dropped when the reply is sent.
    _permit: Permit,
    shared: Arc<Shared>,
}

impl DeferredRead {
    fn run(mut self) {
        let reply = self.reply.take().expect("deferred read replies exactly once");
        if self.shared.is_shutdown() {
            reply.error(libc::EIO);
            return;
        }
        let result = (|| {
            let file = open_lower(Some(self.lazy.as_ref()), &self.relative, &self.source)?;
            read_at(&file, self.offset, self.size)
        })();
        // The worker takes the reply out of the shared slot before I/O, so a
        // shutdown drain cannot answer this read. Re-check the flag instead of
        // returning a success after the mount has closed the queue.
        let shutdown = self.shared.is_shutdown();
        match result {
            Ok(_) if shutdown => reply.error(libc::EIO),
            Ok(data) => reply.data(&data),
            Err(_) if shutdown => reply.error(libc::EIO),
            Err(error) => reply.error(Overlay::err(error)),
        }
    }

    fn reject(mut self, errno: i32) {
        if let Some(reply) = self.reply.take() {
            reply.error(errno);
        }
    }
}

struct Actor {
    overlay: Overlay,
    shared: Arc<Shared>,
    gate: Arc<MutationGate>,
    pool: &'static ReadPool,
}

impl Actor {
    /// Read the gate phase for one actor decision and count a genuinely
    /// observed `Fenced` phase. `MutationGate::fence` never increments this
    /// counter, so a zero delta means the actor's 10 ms poll skipped the
    /// transient fence entirely.
    fn phase(&self) -> GatePhase {
        let phase = self.gate.phase();
        if phase == GatePhase::Fenced {
            self.shared.observe_fenced();
        }
        phase
    }

    fn run(mut self) {
        loop {
            // Shutdown wins over phase handling: a queued mutation must not be
            // executed after close just because the gate still looked healthy.
            if self.shared.is_shutdown() {
                self.fail_frozen(libc::EIO);
                self.fail_ready(libc::EIO);
                self.shared.drain_deferred(libc::EIO);
                return;
            }
            match self.phase() {
                GatePhase::Fenced => self.fail_frozen(libc::EROFS),
                GatePhase::Healthy => self.drain_frozen(),
                GatePhase::Frozen => {}
            }
            if self.shared.is_shutdown() {
                continue;
            }
            let Some(queued) = self.shared.pop_ready_timeout(ACTOR_POLL) else { continue };
            // `pop_ready_timeout` refuses a closed queue, but shutdown can race
            // the successful pop. Do not execute an operation the shim already
            // considers closed.
            if self.shared.is_shutdown() {
                queued.op.fail(libc::EIO);
                continue;
            }
            self.route(queued);
        }
    }

    fn fail_frozen(&mut self, errno: i32) {
        loop {
            let queued = self.shared.lock().pop_frozen_for_drain();
            let Some(queued) = queued else { return };
            queued.op.fail(errno);
        }
    }

    fn fail_ready(&mut self, errno: i32) {
        loop {
            let queued = self.shared.lock().pop_ready_for_drain();
            let Some(queued) = queued else { return };
            queued.op.fail(errno);
        }
    }

    /// Drain the parked mutation FIFO in order once the gate is healthy again.
    fn drain_frozen(&mut self) {
        loop {
            if self.phase() != GatePhase::Healthy {
                return;
            }
            let Some(queued) = self.shared.take_frozen_front() else { return };
            if self.execute(queued) {
                return;
            }
        }
    }

    fn route(&mut self, queued: Queued) {
        let mutation = queued.op.is_mutation();
        match self.phase() {
            GatePhase::Fenced if mutation => queued.op.fail(libc::EROFS),
            GatePhase::Frozen if mutation => self.shared.push_frozen_back(queued),
            _ => {
                self.execute(queued);
            }
        }
    }

    /// Admit and execute one operation. Returns true when a mutation was parked
    /// again because admission raced a new freeze.
    fn execute(&mut self, queued: Queued) -> bool {
        let Queued { op, epoch, _permit: permit } = queued;
        if !op.is_mutation() {
            self.run_op(op, permit);
            return false;
        }
        let gate = self.gate.clone();
        match gate.mutation() {
            Ok(guard) => {
                if !epoch_matches(epoch, guard.epoch()) {
                    self.shared.reject_epoch_mismatch();
                    drop(guard);
                    op.fail(libc::EROFS);
                    return false;
                }
                self.run_op(op, permit);
                drop(guard);
                false
            }
            Err(error) if error.raw_os_error() == Some(libc::EAGAIN) => {
                self.shared.push_frozen_back(Queued { op, epoch, _permit: permit });
                true
            }
            Err(error) => {
                op.fail(Overlay::err(error));
                false
            }
        }
    }

    fn run_op(&mut self, op: OwnedOp, permit: Permit) {
        match op {
            OwnedOp::Lookup { parent, name, reply } => match self.overlay.op_lookup(parent, &name) {
                Ok(attr) => reply.entry(&TTL, &attr, 0),
                Err(error) => reply.error(Overlay::err(error)),
            },
            OwnedOp::Getattr { ino, reply } => match self.overlay.op_getattr(ino) {
                Ok(attr) => reply.attr(&TTL, &attr),
                Err(error) => reply.error(Overlay::err(error)),
            },
            OwnedOp::Readdir { ino, offset, mut reply } => match self.overlay.op_readdir(ino) {
                Ok(rows) => {
                    for (idx, (child, kind, name)) in rows.into_iter().enumerate().skip(offset.max(0) as usize) {
                        if reply.add(child, (idx + 1) as i64, kind, name) {
                            break;
                        }
                    }
                    reply.ok();
                }
                Err(error) => reply.error(Overlay::err(error)),
            },
            OwnedOp::Readlink { ino, reply } => match self.overlay.op_readlink(ino) {
                Ok(target) => reply.data(&target),
                Err(error) => reply.error(Overlay::err(error)),
            },
            OwnedOp::Open { ino, flags, reply } => match self.overlay.op_open(ino, flags) {
                Ok(()) => reply.opened(0, 0),
                Err(error) => reply.error(Overlay::err(error)),
            },
            OwnedOp::Read { ino, offset, size, reply } => self.read(ino, offset, size, reply, permit),
            OwnedOp::Write { ino, offset, data, reply } => match self.overlay.op_write(ino, offset, &data) {
                Ok(count) => reply.written(count),
                Err(error) => reply.error(Overlay::err(error)),
            },
            OwnedOp::Setattr { ino, mode, size, reply } => match self.overlay.op_setattr(ino, mode, size) {
                Ok(attr) => reply.attr(&TTL, &attr),
                Err(error) => reply.error(Overlay::err(error)),
            },
            OwnedOp::Create { parent, name, mode, reply } => match self.overlay.op_create(parent, &name, mode) {
                Ok(attr) => reply.created(&TTL, &attr, 0, 0, 0),
                Err(error) => reply.error(Overlay::err(error)),
            },
            OwnedOp::Mkdir { parent, name, mode, reply } => match self.overlay.op_mkdir(parent, &name, mode) {
                Ok(attr) => reply.entry(&TTL, &attr, 0),
                Err(error) => reply.error(Overlay::err(error)),
            },
            OwnedOp::Unlink { parent, name, reply } => match self.overlay.op_unlink(parent, &name) {
                Ok(()) => reply.ok(),
                Err(error) => reply.error(Overlay::err(error)),
            },
            OwnedOp::Rmdir { parent, name, reply } => match self.overlay.op_rmdir(parent, &name) {
                Ok(()) => reply.ok(),
                Err(error) => reply.error(Overlay::err(error)),
            },
            OwnedOp::Rename { parent, name, newparent, newname, flags, reply } => {
                match self.overlay.op_rename(parent, &name, newparent, &newname, flags) {
                    Ok(()) => reply.ok(),
                    Err(error) => reply.error(Overlay::err(error)),
                }
            }
        }
    }

    fn read(&mut self, ino: u64, offset: i64, size: u32, reply: ReplyData, permit: Permit) {
        match self.overlay.read_plan(ino) {
            Err(error) => reply.error(Overlay::err(error)),
            Ok(ReadPlan::Local(path)) => match self.overlay.read_local(&path, offset, size) {
                Ok(data) => reply.data(&data),
                Err(error) => reply.error(Overlay::err(error)),
            },
            Ok(ReadPlan::Lazy { relative, source, lazy }) => {
                self.submit_deferred(DeferredRead {
                    relative,
                    source,
                    lazy,
                    offset,
                    size,
                    reply: Some(reply),
                    _permit: permit,
                    shared: self.shared.clone(),
                });
            }
        }
    }

    /// Hand a lazy read to the global pool. If the pool is saturated the reply is
    /// `EAGAIN`; the read is never executed inline on the actor.
    fn submit_deferred(&self, deferred: DeferredRead) {
        let slot = Arc::new(Mutex::new(Some(deferred)));
        let request_id = self.shared.register_deferred(slot.clone());
        let job_slot = slot.clone();
        let shared = self.shared.clone();
        let job: ReadJob = Box::new(move || {
            if let Some(deferred) = job_slot.lock().unwrap_or_else(PoisonError::into_inner).take() {
                deferred.run();
            }
            shared.complete_deferred(request_id);
        });
        if let Err(job) = self.pool.execute(job) {
            drop(job);
            self.shared.complete_deferred(request_id);
            if let Some(deferred) = slot.lock().unwrap_or_else(PoisonError::into_inner).take() {
                deferred.reject(libc::EAGAIN);
            }
        }
    }
}

/// A queued mutation may run only under the lease epoch it was stamped with.
fn epoch_matches(queued: Option<i64>, guard: i64) -> bool {
    queued == Some(guard)
}

pub(super) struct Dispatcher {
    shared: Arc<Shared>,
    mount_budget: Arc<Budget>,
    global_budget: Arc<Budget>,
    /// Kept for enqueue-time epoch stamping and shutdown fencing.
    gate: Arc<MutationGate>,
    worker: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl Dispatcher {
    pub(super) fn start(overlay: Overlay) -> io::Result<Arc<Self>> {
        let gate = overlay.gate.clone();
        let shared = Shared::new();
        let mount_budget = Arc::new(Budget::new(MOUNT_QUEUE_OPS, MOUNT_QUEUE_BYTES));
        let global_budget = global_budget();
        let pool = global_read_pool()?;
        let dispatcher = Arc::new(Self {
            shared: shared.clone(),
            mount_budget,
            global_budget,
            gate: gate.clone(),
            worker: Mutex::new(None),
        });
        let actor = Actor { overlay, shared, gate, pool };
        let handle = std::thread::Builder::new().name("rootyard-fuse-actor".into()).spawn(move || actor.run())?;
        *dispatcher.worker.lock().unwrap_or_else(PoisonError::into_inner) = Some(handle);
        Ok(dispatcher)
    }

    pub(super) fn enqueue(&self, op: OwnedOp) -> Result<(), Reject> {
        if self.shared.is_shutdown() {
            return Err(Reject::Closed(op));
        }
        // Stamp only mutations. Reads are not gated and do not need admission.
        let epoch = op.is_mutation().then(|| self.gate.epoch());
        let bytes = op.payload_bytes();
        let Some(permit) = Permit::acquire(&self.mount_budget, &self.global_budget, bytes) else {
            return Err(Reject::Saturated(op));
        };
        match self.shared.push_ready(Queued { op, epoch, _permit: permit }) {
            None => Ok(()),
            Some(queued) => Err(Reject::Closed(queued.op)),
        }
    }

    pub(super) fn usage(&self) -> QueueUsage {
        let (mount_ops, mount_bytes) = self.mount_budget.used();
        let (global_ops, global_bytes) = self.global_budget.used();
        let (ready, frozen) = self.shared.lens();
        let pending_reads = self.shared.pending_deferred();
        let (fence_observations, epoch_mismatch_rejections) = self.shared.diagnostics();
        QueueUsage {
            mount_ops,
            mount_bytes,
            global_ops,
            global_bytes,
            ready,
            frozen,
            pending_reads,
            fence_observations,
            epoch_mismatch_rejections,
        }
    }

    pub(super) fn shutdown(&self) {
        // Fence first so no replay can admit a new mutation, then close the
        // queue and let the actor fail everything still queued with EIO.
        self.gate.fence();
        self.shared.close();
        let handle = self.worker.lock().unwrap_or_else(PoisonError::into_inner).take();
        if let Some(handle) = handle {
            let _ = handle.join();
        }
    }
}

impl Drop for Dispatcher {
    fn drop(&mut self) {
        self.gate.fence();
        self.shared.close();
        if let Some(handle) = self.worker.lock().unwrap_or_else(PoisonError::into_inner).take() {
            let _ = handle.join();
        }
    }
}

/// Kernel-facing shim state. Dropping it stops the actor, which drains every
/// queued reply with one error instead of leaking it.
pub(super) struct MountFs {
    dispatcher: Arc<Dispatcher>,
}

impl MountFs {
    pub(super) fn new(overlay: Overlay) -> io::Result<Self> {
        Ok(Self { dispatcher: Dispatcher::start(overlay)? })
    }

    pub(super) fn dispatcher(&self) -> &Arc<Dispatcher> {
        &self.dispatcher
    }

    pub(super) fn dispatch(&self, op: OwnedOp) {
        match self.dispatcher.enqueue(op) {
            Ok(()) => {}
            Err(Reject::Saturated(op)) => op.fail(libc::EAGAIN),
            Err(Reject::Closed(op)) => op.fail(libc::EIO),
        }
    }
}

impl Drop for MountFs {
    fn drop(&mut self) {
        self.dispatcher.shutdown();
    }
}

#[cfg(test)]
#[path = "fuse_dispatch/tests.rs"]
mod tests;
