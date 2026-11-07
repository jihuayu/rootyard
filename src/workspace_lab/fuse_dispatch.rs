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
//! Every queued operation holds an RAII [`Permit`] charged against both budgets
//! until its reply is sent, so queued bytes and delayed read replies are counted,
//! not only the frozen FIFO. Delayed lazy reads are handed to the global read
//! pool (4 workers, 256 jobs); saturation replies `EAGAIN` instead of doing the
//! read inline on the actor. Deferred jobs always own their reply and therefore
//! send exactly one reply even when the mount shuts down.
use super::inner_ops::{ReadPlan, read_at};
use super::owned_ops::OwnedOp;
use super::*;
use fuser::ReplyData;
use std::collections::VecDeque;
use std::sync::{
    Condvar, Mutex, MutexGuard, OnceLock, PoisonError,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

pub const MOUNT_QUEUE_OPS: usize = 128;
pub const MOUNT_QUEUE_BYTES: usize = 8 * 1024 * 1024;
const GLOBAL_QUEUE_OPS: usize = 1024;
const GLOBAL_QUEUE_BYTES: usize = 32 * 1024 * 1024;
/// Upper bound on how long the actor waits before re-checking the gate phase.
pub const ACTOR_POLL: Duration = Duration::from_millis(10);
const READ_WORKERS: usize = 4;
const READ_JOBS: usize = 256;

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
}

/// Why the shim could not enqueue. Saturation is the only `EAGAIN`; a closed
/// queue after shutdown replies `EIO`.
pub(super) enum Reject {
    Saturated(OwnedOp),
    Closed(OwnedOp),
}

struct Budget {
    limit_ops: usize,
    limit_bytes: usize,
    used: Mutex<(usize, usize)>,
}

impl Budget {
    fn new(limit_ops: usize, limit_bytes: usize) -> Self {
        Self { limit_ops, limit_bytes, used: Mutex::new((0, 0)) }
    }

    fn lock(&self) -> MutexGuard<'_, (usize, usize)> {
        self.used.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn try_acquire(&self, bytes: usize) -> bool {
        let mut used = self.lock();
        let Some(ops) = used.0.checked_add(1) else { return false };
        let Some(total) = used.1.checked_add(bytes) else { return false };
        if ops > self.limit_ops || total > self.limit_bytes {
            return false;
        }
        *used = (ops, total);
        true
    }

    fn release(&self, bytes: usize) {
        let mut used = self.lock();
        used.0 = used.0.saturating_sub(1);
        used.1 = used.1.saturating_sub(bytes);
    }

    fn used(&self) -> (usize, usize) {
        *self.lock()
    }
}

fn global_budget() -> Arc<Budget> {
    static GLOBAL: OnceLock<Arc<Budget>> = OnceLock::new();
    GLOBAL.get_or_init(|| Arc::new(Budget::new(GLOBAL_QUEUE_OPS, GLOBAL_QUEUE_BYTES))).clone()
}

/// RAII charge against the per-mount budget and the process-wide helper budget.
/// Released exactly once, on every path, when the operation's reply is sent.
struct Permit {
    mount: Arc<Budget>,
    global: Arc<Budget>,
    bytes: usize,
}

impl Permit {
    fn acquire(mount: &Arc<Budget>, global: &Arc<Budget>, bytes: usize) -> Option<Self> {
        if !mount.try_acquire(bytes) {
            return None;
        }
        if !global.try_acquire(bytes) {
            mount.release(bytes);
            return None;
        }
        Some(Self { mount: mount.clone(), global: global.clone(), bytes })
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        self.global.release(self.bytes);
        self.mount.release(self.bytes);
    }
}

struct Queued {
    op: OwnedOp,
    _permit: Permit,
}

struct QueueState {
    ready: VecDeque<Queued>,
    frozen: VecDeque<Queued>,
    shutdown: bool,
}

struct Shared {
    state: Mutex<QueueState>,
    wake: Condvar,
    /// Deferred lazy reads that still own an unsent reply, so shutdown can
    /// drain them instead of waiting for a pool worker.
    deferred: Mutex<Vec<(u64, Arc<Mutex<Option<DeferredRead>>>)>>,
    next_deferred: AtomicUsize,
}

impl Shared {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(QueueState { ready: VecDeque::new(), frozen: VecDeque::new(), shutdown: false }),
            wake: Condvar::new(),
            deferred: Mutex::new(Vec::new()),
            next_deferred: AtomicUsize::new(0),
        })
    }

    fn lock(&self) -> MutexGuard<'_, QueueState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn push_ready(&self, queued: Queued) -> Result<(), Queued> {
        let mut state = self.lock();
        if state.shutdown {
            return Err(queued);
        }
        state.ready.push_back(queued);
        drop(state);
        self.wake.notify_all();
        Ok(())
    }

    fn push_frozen_back(&self, queued: Queued) {
        self.lock().frozen.push_back(queued);
        self.wake.notify_all();
    }

    fn take_frozen_front(&self) -> Option<Queued> {
        self.lock().frozen.pop_front()
    }

    fn pop_ready_timeout(&self, timeout: Duration) -> Option<Queued> {
        let mut state = self.lock();
        if state.ready.is_empty() && !state.shutdown {
            let (next, _) = self.wake.wait_timeout(state, timeout).unwrap_or_else(PoisonError::into_inner);
            state = next;
        }
        state.ready.pop_front()
    }

    fn is_shutdown(&self) -> bool {
        self.lock().shutdown
    }

    fn close(&self) {
        self.lock().shutdown = true;
        self.wake.notify_all();
    }

    fn lens(&self) -> (usize, usize) {
        let state = self.lock();
        (state.ready.len(), state.frozen.len())
    }

    fn register_deferred(&self, slot: Arc<Mutex<Option<DeferredRead>>>) -> u64 {
        let id = self.next_deferred.fetch_add(1, Ordering::Relaxed) as u64;
        self.deferred.lock().unwrap_or_else(PoisonError::into_inner).push((id, slot));
        id
    }

    fn complete_deferred(&self, id: u64) {
        self.deferred.lock().unwrap_or_else(PoisonError::into_inner).retain(|(candidate, _)| *candidate != id);
    }

    fn pending_deferred(&self) -> usize {
        self.deferred.lock().unwrap_or_else(PoisonError::into_inner).len()
    }

    /// Reply to every still-pending deferred read with one errno. Whichever
    /// thread wins the per-slot `Option` sends the single reply; the other path
    /// sees `None` and leaves it alone.
    fn drain_deferred(&self, errno: i32) {
        let entries = std::mem::take(&mut *self.deferred.lock().unwrap_or_else(PoisonError::into_inner));
        for (_, slot) in entries {
            if let Some(deferred) = slot.lock().unwrap_or_else(PoisonError::into_inner).take() {
                deferred.reject(errno);
            }
        }
    }
}

type ReadJob = Box<dyn FnOnce() + Send + 'static>;

/// Global bounded pool for lazy lower-layer hydration/pread. Saturation is
/// reported to the caller so the actor can reply `EAGAIN` instead of blocking.
struct ReadPool {
    queue: Mutex<VecDeque<ReadJob>>,
    ready: Condvar,
    capacity: usize,
    closed: AtomicBool,
}

impl ReadPool {
    fn new(workers: usize, capacity: usize) -> io::Result<Arc<Self>> {
        let pool = Arc::new(Self {
            queue: Mutex::new(VecDeque::new()),
            ready: Condvar::new(),
            capacity,
            closed: AtomicBool::new(false),
        });
        for index in 0..workers {
            let worker = pool.clone();
            let result =
                std::thread::Builder::new().name(format!("rootyard-fuse-read-{index}")).spawn(move || worker.run());
            if let Err(error) = result {
                pool.close();
                return Err(error);
            }
        }
        Ok(pool)
    }

    fn execute(&self, job: ReadJob) -> Result<(), ReadJob> {
        let mut queue = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
        if self.closed.load(Ordering::Acquire) || queue.len() >= self.capacity {
            return Err(job);
        }
        queue.push_back(job);
        drop(queue);
        self.ready.notify_one();
        Ok(())
    }

    fn run(&self) {
        loop {
            let job = {
                let mut queue = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
                while queue.is_empty() && !self.closed.load(Ordering::Acquire) {
                    queue = self.ready.wait(queue).unwrap_or_else(PoisonError::into_inner);
                }
                queue.pop_front()
            };
            match job {
                Some(job) => job(),
                None => return,
            }
        }
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.ready.notify_all();
    }
}

fn read_pool() -> io::Result<&'static ReadPool> {
    static POOL: OnceLock<Result<Arc<ReadPool>, String>> = OnceLock::new();
    POOL.get_or_init(|| ReadPool::new(READ_WORKERS, READ_JOBS).map_err(|e| e.to_string()))
        .as_ref()
        .map(|pool| pool.as_ref())
        .map_err(|error| io::Error::other(error.clone()))
}

/// A lazy read whose reply and budget charge travel to the read pool together.
struct DeferredRead {
    relative: PathBuf,
    source: Entry,
    lazy: Arc<dyn LazySource>,
    offset: i64,
    size: u32,
    reply: Option<ReplyData>,
    permit: Permit,
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
        match result {
            Ok(data) => reply.data(&data),
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
    fn run(mut self) {
        loop {
            match self.gate.phase() {
                GatePhase::Fenced => self.fail_frozen(libc::EROFS),
                GatePhase::Healthy => self.drain_frozen(),
                GatePhase::Frozen => {}
            }
            if self.shared.is_shutdown() {
                self.fail_frozen(libc::EIO);
                self.fail_ready(libc::EIO);
                self.shared.drain_deferred(libc::EIO);
                return;
            }
            if let Some(queued) = self.shared.pop_ready_timeout(ACTOR_POLL) {
                self.route(queued);
            }
        }
    }

    fn fail_frozen(&mut self, errno: i32) {
        while let Some(queued) = self.shared.take_frozen_front() {
            queued.op.fail(errno);
        }
    }

    fn fail_ready(&mut self, errno: i32) {
        loop {
            let mut state = self.shared.lock();
            let Some(queued) = state.ready.pop_front() else { return };
            drop(state);
            queued.op.fail(errno);
        }
    }

    /// Drain the parked mutation FIFO in order once the gate is healthy again.
    fn drain_frozen(&mut self) {
        loop {
            if self.gate.phase() != GatePhase::Healthy {
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
        match self.gate.phase() {
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
        let Queued { op, _permit: permit } = queued;
        if !op.is_mutation() {
            self.run_op(op, permit);
            return false;
        }
        let gate = self.gate.clone();
        match gate.mutation() {
            Ok(guard) => {
                self.run_op(op, permit);
                drop(guard);
                false
            }
            Err(error) if error.raw_os_error() == Some(libc::EAGAIN) => {
                self.shared.push_frozen_back(Queued { op, _permit: permit });
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
                    permit,
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

pub(super) struct Dispatcher {
    shared: Arc<Shared>,
    mount_budget: Arc<Budget>,
    global_budget: Arc<Budget>,
    gate: Arc<MutationGate>,
    worker: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl Dispatcher {
    pub(super) fn start(overlay: Overlay) -> io::Result<Arc<Self>> {
        let gate = overlay.gate.clone();
        let shared = Shared::new();
        let mount_budget = Arc::new(Budget::new(MOUNT_QUEUE_OPS, MOUNT_QUEUE_BYTES));
        let global_budget = global_budget();
        let pool = read_pool()?;
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
        let bytes = op.payload_bytes();
        let Some(permit) = Permit::acquire(&self.mount_budget, &self.global_budget, bytes) else {
            return Err(Reject::Saturated(op));
        };
        match self.shared.push_ready(Queued { op, _permit: permit }) {
            Ok(()) => Ok(()),
            Err(queued) => Err(Reject::Closed(queued.op)),
        }
    }

    pub(super) fn usage(&self) -> QueueUsage {
        let (mount_ops, mount_bytes) = self.mount_budget.used();
        let (global_ops, global_bytes) = self.global_budget.used();
        let (ready, frozen) = self.shared.lens();
        let pending_reads = self.shared.pending_deferred();
        QueueUsage { mount_ops, mount_bytes, global_ops, global_bytes, ready, frozen, pending_reads }
    }

    pub(super) fn shutdown(&self) {
        self.shared.close();
        let handle = self.worker.lock().unwrap_or_else(PoisonError::into_inner).take();
        if let Some(handle) = handle {
            let _ = handle.join();
        }
    }
}

impl Drop for Dispatcher {
    fn drop(&mut self) {
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
mod tests {
    use super::*;

    #[test]
    fn budget_caps_ops_and_bytes_and_releases_exactly() {
        let budget = Budget::new(2, 100);
        assert!(budget.try_acquire(60));
        assert!(!budget.try_acquire(50), "byte cap must reject oversize operations");
        assert!(budget.try_acquire(40));
        assert!(!budget.try_acquire(1), "operation cap must reject a third operation");
        assert_eq!(budget.used(), (2, 100));
        budget.release(60);
        assert_eq!(budget.used(), (1, 40));
        budget.release(40);
        assert_eq!(budget.used(), (0, 0));
    }

    #[test]
    fn permit_charges_both_budgets_and_releases_on_drop() {
        let mount = Arc::new(Budget::new(8, 1024));
        let global = Arc::new(Budget::new(8, 2048));
        let permit = Permit::acquire(&mount, &global, 128).expect("permit");
        assert_eq!(mount.used(), (1, 128));
        assert_eq!(global.used(), (1, 128));
        drop(permit);
        assert_eq!(mount.used(), (0, 0));
        assert_eq!(global.used(), (0, 0));
    }
}
