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

Every queued mutation is stamped with the lease epoch that was authorized when
the shim enqueued it. The actor admits the mutation exactly once and compares
the resulting guard's epoch with the stamp. If the gate moved to a newer lease
while the operation was parked, the actor drops the guard and replies `EROFS`
without executing the operation. This covers the case where the 10 ms poll
misses a transient `Fenced` phase and only observes the new `Healthy` epoch:
the old queued write still cannot run on the new authority.

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
paths). A read reserves its reply size in the same byte budget, and
`QueueUsage::pending_reads` counts deferred reads with a registered slot,
including a worker currently executing I/O outside the slot lock. Shutdown can
answer only the replies still in their slot. A worker that already took its
slot re-checks the shutdown flag after I/O and replies `EIO`, so it cannot send
a late success and does not reply twice. The accounting therefore covers
operations already sitting in the channel/ready queue, parked frozen
operations and delayed read replies — not just the frozen FIFO. A rejected
enqueue releases its partial charge immediately.

## Delayed reads

Lazy lower-layer reads still use one global pool with 4 workers and a 256-job
queue. The old inline fallback is removed: if the pool is saturated the actor
replies `EAGAIN` and keeps its own loop free. A deferred job owns its
`ReplyData`, its budget permit and a marker for the owning queue, so it always
sends exactly one reply — including after mount shutdown, where it replies
`EIO` instead of touching a lower source. Queue limits are per mount, so a slow
read on one mount cannot stall another mount's actor. A deferred job owns its
`ReplyData`, its budget permit and a marker for the owning queue, so it sends
exactly one reply. The worker takes the reply out of the shared slot before it
starts I/O; shutdown therefore cannot answer a read that is already in flight.
The worker checks the shutdown flag after I/O and replies `EIO` instead of a
late success. Joining an in-flight lower-source read remains part of the helper
lifecycle; this same-process dispatch loop does not claim it has drained that
I/O.

## Shutdown and fake-session limits

Dropping `MountFs` (session unmount) or calling `MountHandle::shutdown` stops the
actor. Shutdown fences the gate first, then closes the queue. The actor checks
shutdown before any gate phase handling, and the queue's ordinary pop refuses a
closed queue; only the explicit fail-ready/fail-frozen drain paths may remove
entries after close. Ready and parked operations therefore reply `EIO` and
cannot execute after shutdown, while a mutation that was already admitted may
still finish. This is still only a same-process session: an operator `SIGKILL`
of the API process can still leave a blocked `request_wait_answer` in the
kernel and cannot be fenced by this prototype. Queue contents are memory only
and are lost on process death.

## Verification

`tests/fuse_freeze_queue.rs` contains strict native kernel FUSE acceptance tests,
not unit mirrors. Every test is marked
`#[ignore = "requires ROOTYARD_FUSE_NATIVE=1 and a working /dev/fuse"]`. A default
run therefore does not execute it, and an explicit `--ignored` run without
`ROOTYARD_FUSE_NATIVE=1` fails its first assertion instead of passing. The tests
use blocking syscalls, bounded channel waits and owned temporary directories:

1. **Same-offset FIFO with two aliases.** A private-upper file and a second
   path hardlinked to the same host inode (`MetadataExt::ino` equality) are
   opened read-write before the freeze, so no `Open` is queued. The overlay
   allocates a different FUSE inode per path, so the two aliases avoid the VFS
   same-inode lock. The first `FileExt::write_at` parks; the test waits for
   `frozen == 1`, starts the second write and waits for `frozen == 2`. Only the
   thaw's arrival order makes both writes return 6 and the second payload win at
   host offset 0; a reversed drain would fail. While frozen, a read-only read on
   that mount still returns the original six bytes, and a second real mount with
   its own gate/actor/queue creates, writes and reads successfully. The hardlink
   pair is an owned artificial fixture; this does not claim production hardlink
   semantics are complete.
2. **Direct fence.** A new create returns `EROFS`, the upper layer has no such
   file, reads still work, and the actor-observed fence counter increases.
3. **Rapid freeze/fence/handoff.** The gate is frozen with an old-epoch write
   parked, `freeze_then_fence` returns, and the same freezer thread immediately
   hands off the next epoch, so the actor's 10 ms poll may observe only the new
   `Healthy` epoch. Two fixed-cardinality, process-local counters are exposed:
   `fence_observations` is incremented only where the actor itself reads a
   `Fenced` phase (never by `MutationGate::fence`), and
   `epoch_mismatch_rejections` counts parked mutations dropped because their
   enqueue epoch no longer matches admission. Every round must return `EROFS`
   with unchanged upper bytes. A round whose fence-observation delta is nonzero
   only proves the direct fence path and is retried; at most 32 rounds are
   tried and at least one must have a zero fence-observation delta together with
   a positive epoch-mismatch delta. That zero-delta round is the missed-fence
   coverage, and a subsequent new-epoch write must succeed. Code without the
   enqueue epoch stamp would have executed the stale write in that round.
4. **Budgets.** Once replies drain, mount/global ops and bytes, `ready`,
   `frozen` and `pending_reads` are zero. The diagnostic counters are cumulative
   observations, so they are deliberately excluded from that leak check.

Run on a host/user namespace with a working `/dev/fuse` (coordinator only):

```text
ROOTYARD_FUSE_NATIVE=1 cargo test --test fuse_freeze_queue -- --ignored --test-threads=1
```

`--test-threads=1` keeps the process-wide helper budget and read pool
single-owner for these mounts. Without `ROOTYARD_FUSE_NATIVE=1` an explicit
`--ignored` run fails; a default run skips the ignored tests. Neither result may
be reported as passed native evidence. The optional shutdown-with-queued-work
case is **not** covered yet and remains pending.

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
