# Isolated workspace FUSE sessions and raw frozen snapshots

Issues #91 and #95: a service that reads its own FUSE mount while it is frozen
can wait on the same writer that needs the freeze to finish. Keeping the FUSE
session inside that service also makes hard process death a kernel-I/O hazard.

The new opt-in `fuse-helper` backend owns sessions in a separate process, with
private control/heartbeat descriptors, bounded RPC queues and deadlines, epoch
and operation binding, and a bounded child reaper. Frozen capture, checkpoint
and restore use the validated lower/upper/whiteout/lazy snapshot directly.
They do not traverse the frozen kernel mount. Restore publication uses owned
no-replace guards and retains possibly committed data on uncertain SQL commit.

For graceful teardown the helper fences and drains, verifies the single owned
mount identity, performs a normal non-lazy unmount and joins its session.
Every teardown holds its own workspace reservation through completion. Shutdown
is linearized against registration, reuse and publication, cancels pending
builders and waits for their cleanup under an independent watchdog. Its ACK
means shutdown was accepted; already-admitted RPC replies may finish out of
order. Exit zero means the cleanup barrier finished. Any ambiguous identity,
unmount failure, deadline overrun or unverifiable mount capture fails closed.
AutoUnmount remains enabled for abrupt helper/parent loss.

## Exact native acceptance

Parent-integrated source `51d9a62` used binary SHA-256
`f901cbc58e1bd6af2e1e079d8d43e6a1a349c9f433ac739503f4cfc8fdc1a23b`,
compiled-input SHA-256
`0809c16904246bc3f17621a03798de806496275a1c774b2c92b9a7898a53f88e`.

- All-target Clippy passed. The 67 laboratory unit tests passed before this
  parent merge; the helper and workspace source files were unchanged by it.
- All fourteen native lifecycle/RPC cases passed with source, binary and harness
  receipts matching. They include real freeze/thaw, fence/handoff, cancellation,
  zero-exit normal cleanup, heartbeat loss, child SIGKILL, independent-parent
  SIGKILL and same-workspace concurrent requests leaving one kernel mount.
  All owned mounts, helpers and writers were gone before final cleanup finished.
- The real API/editor/sandbox flow passed: rename/chmod, Git index, incremental
  capture, checkpoint bytes/mode, lease-loss job cancellation and hard API
  restart/remount. This replaces the formerly blocking path with an actual run.
- The formerly blocking remote-handoff test passed against the real object
  store: publish COMMITTED, remove the source volume, attach on a second volume,
  lease epoch fencing, sparse lazy baseline, prewarm/cache, bounded offline
  failure, concurrent reads, native compilation/mmap and dirty rename.
  This is a loopback second-volume test, not an independent physical host.
- Luna Max reviewed the ownership, shutdown, reaper and raw snapshot corrections
  and found no remaining concrete P1/P2 under the documented namespace contract.
  No new D-state threads were observed; old baseline failures remain retained.

Receipts and raw unittest results are in `round5-fuse-helper-evidence/`.
Test-only backend/binary selectors also cover the handoff harness. Later Python
and documentation changes do not alter the compiled inputs above.

## Remaining qualification

The backend is opt-in. The historical in-process `fuse` backend retains its
lifecycle limitation. AutoUnmount is qualified here only for namespace root in a
private user/mount namespace with fusermount3, keeping the session owner ACL.
A conventional non-root host, including its `user_allow_other` policy, is not
qualified. No host fuse.conf or LSM policy was changed.

Queued-writer SIGKILL was exercised through the actual helper and an external
RPC parent stub. The API scenario hard-killed the actual service and remounted,
but it did not deterministically park a kernel writer during that API kill or
inject remote-publish exit-77 at that point. That issue-#91 gate remains open.
Physical host/storage failure qualification remains outside these loopback
results. No issue is closed or production rollout claimed by this record.
