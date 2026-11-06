# Workspace live FUSE review: 2ef7ee7, 543a5e4, 1d77138

Reviewed source HEAD `1d77138859fc051521702d4efa9a847416a7a04b`; native executable SHA-256 `9beb9e5d61570117bf2c0b8f583204fb9c38bdba11a5a923b1638ea32efc2b14`. Tests used the actual Rootyard process and shared PostgreSQL 17 test environment; no simulation.

Independent command:
```sh
source /workspace/shared/rootyard-env.sh
python3 -m unittest tests.test_workspace_fuse tests.test_workspace_fuse_service -v
```

Result: PASS, 3/3. This exercised kernel FUSE copy-on-write and moved-symlink confinement plus HTTP/PostgreSQL live editor save, chmod, ignore rules, Git index view, checkpoint capture, lease cancellation, and restart remount.

Findings sent to workspace executor and parent:
- FUSE-mode cross-host lease takeover is unreachable. `lease()` calls `service::locked()`, which requires `mounts::mounted(id)`; a new host does not mount rows assigned to the old host during startup, and lease commit only updates an existing local gate. The SQL expired-lease takeover condition is therefore unreachable on that host. Executor accepted and plans a committed-checkpoint-only takeover path with a native two-volume regression.
- An already-admitted mutation callback can finish after its deadline: `MutationGate::mutation()` checks the deadline once, then the callback keeps a read guard; lease refresh/update only changes the atomic deadline, without draining active guards. Executor accepted the limitation and will explicitly scope lease semantics to local mutation admission and DB publication; stale host cannot publish after epoch loss, and same-host handoff will drain local callbacks. This remains a safety acceptance boundary to re-review against the new native test and docs.

No source changes made by reviewer.

## Handoff re-review: 7089b69

Reviewed 7089b69 plus source-read lease follow-up 0d72db8. The FUSE-mode new-host blocker is fixed by allowing the lease path to skip the old host's local-mount requirement, requiring an expired source lease and a committed latest checkpoint, restoring that checkpoint onto the target volume, then mounting the existing workspace ID with the incremented epoch. Same-host lease updates freeze the gate through the database commit.

Independent native evidence:
```sh
source /workspace/shared/rootyard-env.sh
source /tmp/rootyard-garage-test/env
python3 -m unittest tests.test_workspace_handoff -v
```
PASS 1/1 in 5.1s with PostgreSQL 17, live Garage, real user namespace/FUSE, native Rootyard binary SHA-256 `2b3fca5e972aa9819fc080c6d29dfd01b47d61d6cdfcc016967d563499c4c961`. The test deletes the source volume, rejects an unexpired handoff and unauthorized actor, rehydrates the committed checkpoint on a second volume, reads through the new service mount, increments the lease epoch, and rejects stale-epoch writes.

Residual acceptance limits: this test stops the old service before takeover; it does not test an alive old host after another host takes its lease, nor the same-host in-flight FUSE callback drain. The docs now state old-host callback writes may complete locally but cannot publish after epoch handoff. Review of the publication CAS supports that statement: the final checkpoint commit requires current host, epoch, and unexpired lease. The two-volume test does not exercise that concurrent old-host race directly.
