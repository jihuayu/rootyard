# FUSE dispatch phase 2: bounded per-mount freeze queue

**Status: prototype / pre-helper only. This does not complete issue #91.**

The production mount in `src/workspaces/mounts.rs` now dispatches through a
bounded queue and one actor thread per mount. That is still a process-local
prototype: the session is a `fuser::BackgroundSession` inside the API process,
there is no independent FUSE child, no helper protocol/IPC, no heartbeat and no
parent-loss lifecycle. Those remain the next phase and have no native
acceptance here. No statement in this document claims #91 is done, and the
native FUSE test was written but **not executed by the implementation worker**
(Cargo/build/native runs are performed by the coordinator).

## Why

Previously the kernel shim (`impl Filesystem`) executed every operation on the
single FUSE session thread and admitted a mutation with a thread-local
`MutationGuard` obtained through a macro. A freeze therefore surfaced as an
immediate `EAGAIN` to the editor, and one slow lazy read on the session thread
stalled every other request of that session. The gate also had no way to wake a
waiting dispatcher without a new kernel request.

## Layering

| File | Role |
|------|------|
| `src/workspace_lab/fuse_ops.rs` | `impl Filesystem for MountFs`: copies name/data/arguments into an `OwnedOp` with its `fuser` reply and `try_send`s it. It executes no overlay work and never waits. |
| `src/workspace_lab/owned_ops.rs` | `OwnedOp` variants (owned `OsString`/`Vec<u8>`/reply), mutation classification, payload accounting, one-shot `fail(errno)`. |
| `src/workspace_lab/inner_ops.rs` | Original overlay logic extracted as `Overlay::op_*`/`read_plan`, with no `Request` and no reply. Path-guard helpers (`Entry`, `safe_link_at`, `/proc/self/fd` walk, whiteouts, CoW `prepare`) are preserved. |
| `src/workspace_lab/fuse_dispatch.rs` | Bounded queues, RAII budgets, the per-mount actor, the global read pool and the gate poll. |
| `src/workspace_lab/fuse_mount.rs` | Overlay core plus `spawn()`/`mount()` and `MountHandle::queue_usage()`. |

The actor is the **only** thread that owns `Overlay` and the only caller of
`MutationGate::mutation`, exactly once per mutation. The old admission macro is
gone, so a mutation cannot be admitted in the shim and then advertised again in
the actor; a `MutationGuard` is never moved across threads (its TLS bookkeeping
is only valid on the admitting thread).

## Admission policy

| Gate phase | Writes/create/setattr/mkdir/unlink/rmdir/rename/write-open | Reads, lookup, readlink, readdir, read-only open |
|------------|------------------------------------------------------------|--------------------------------------------------|
| `Healthy` | executed after one admission | executed |
| `Frozen` | parked in a bounded FIFO, reply held | executed |
| `Fenced` | `EROFS` (parked entries drained with `EROFS`, new mutations rejected) | executed |

After a successful thaw the actor drains the parked FIFO in arrival order. The
actor learns about the thaw from a bounded `recv_timeout` poll of **10 ms**
(`ACTOR_POLL`) plus a condvar notification on every enqueue; it never needs a
new kernel request. A fence is terminal for the current epoch, so parked
replies fail with `EROFS` and later mutations fail with `EROFS` without
changing content.

Only a queue-limit breach replies `EAGAIN`. A normal freeze parks writes until
the thaw succeeds; it does not turn editor writes into `EAGAIN`.

## Bounds and accounting

| Budget | Ops | Bytes |
|--------|-----|-------|
| Per mount queue | 128 | 8 MiB |
| All mounts in this process (helper-wide) | 1024 | 32 MiB |

Every enqueued `OwnedOp` acquires an RAII `Permit` charged against both budgets
before it enters the ready queue; the charge is released exactly once when the
reply is sent (including reply-error, fence-drain, shutdown and deferred-read
paths). The accounting therefore covers operations already sitting in the
channel/ready queue, parked frozen operations and delayed read replies — not
just the frozen FIFO. A rejected enqueue releases its partial charge
immediately.

## Delayed reads

Lazy lower-layer reads still use one global pool with 4 workers and a 256-job
queue. The old inline fallback is removed: if the pool is saturated the actor
replies `EAGAIN` and keeps its own loop free. A deferred job owns its
`ReplyData`, its budget permit and a marker for the owning queue, so it always
sends exactly one reply — including after mount shutdown, where it replies
`EIO` instead of touching a lower source. Queue limits are per mount, so a slow
read on one mount cannot stall another mount's actor.

## Shutdown and fake-session limits

Dropping `MountFs` (session unmount) stops the actor; the actor drains every
ready and parked operation with `EIO`/`EROFS` and exits. This is still only a
same-process session: an operator `SIGKILL` of the API process can still leave a
blocked `request_wait_answer` in the kernel and cannot be fenced by this
prototype. Queue contents are memory only and are lost on process death.

## Verification

`tests/fuse_freeze_queue.rs` is a real kernel FUSE test (not a unit mirror). It
mounts an overlay through the new dispatcher and asserts, with blocking
syscalls and channels rather than sleeps:

1. a frozen create parks (the writer stays blocked, not `EAGAIN`);
2. an independent read of another file completes while the create is parked;
3. a second create also parks, in FIFO order;
4. the thaw drains both creates in arrival order into the upper CoW layer;
5. a fenced create returns `EROFS` while reads still work;
6. per-mount and global queue budgets return to zero.

Run on a host/user namespace with a working `/dev/fuse` (coordinator only):

```text
ROOTYARD_FUSE_NATIVE=1 cargo test --test fuse_freeze_queue
```

Without `ROOTYARD_FUSE_NATIVE=1` the test prints a skip notice and returns; it
must not be reported as passed evidence.

## Still open (next phase)

- Independent FUSE child process/helper; the gate is still process-local and
  cannot fence a second process or an arbitrary host writer.
- Helper protocol/IPC, heartbeat, parent-loss and orphan unmount handling.
- Durable or cross-process queueing; this queue is in-memory.
- Per-operation queued-byte accounting for read replies is bounded by the same
  budgets, but the 8 MiB per-mount cap covers queued operations, not the
  in-flight bytes of a read already executing in the pool.
- Native acceptance of `tests/fuse_freeze_queue.rs` and the full service FUSE
  suite is a coordinator job.
