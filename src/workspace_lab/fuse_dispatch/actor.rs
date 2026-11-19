//! Per-mount actor: owns the overlay and executes queued operations.

use super::read_pool::ReadPool;
use super::*;

pub(super) struct Actor {
    pub(super) overlay: Overlay,
    pub(super) shared: Arc<Shared>,
    gate: Arc<MutationGate>,
    pub(super) pool: &'static ReadPool,
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
}

/// Start the single per-mount actor thread with the fixed fixture-visible name.
pub(super) fn spawn(
    overlay: Overlay,
    shared: Arc<Shared>,
    gate: Arc<MutationGate>,
    pool: &'static ReadPool,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    let actor = Actor { overlay, shared, gate, pool };
    std::thread::Builder::new().name("rootyard-fuse-actor".into()).spawn(move || actor.run())
}
