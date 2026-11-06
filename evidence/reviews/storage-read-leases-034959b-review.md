# Storage PostgreSQL read-lease review: 034959b

Review target: commit 034959bf19e5062d3c2e4615c968c75835b3a97b; inspected its exact patch and merged integrated callsites in storage worktree HEAD b228076 (two source edits were uncommitted during review). No source changes made by reviewer.

Independent native check:
```sh
source /workspace/shared/rootyard-env.sh
cargo test --lib storage::read_leases::tests::postgres_barrier_fences_other_pool_connections -- --nocapture
```
PASS 1/1 against PostgreSQL 17.11. It proved that a shared transaction advisory lock held through one pool prevents a distinct pool from acquiring exclusive, that Drop releases it, and that shared readers are denied while exclusive is held.

Findings sent to storage executor and parent:
- Cancellation leak: after tokio::spawn, cancellation of acquire() while awaiting ready_recv drops JoinHandle, which detaches the heartbeat task. If the background task acquires its shared lock, it has no Lease owner to abort it and can hold its pooled connection/lock forever. Executor confirmed and is adding abort-on-drop plus a live two-pool cancellation regression.
- Heartbeat blackhole: ensure_active() only checks a bool/task completion, so a stuck tx.simple_query("SELECT 1") leaves the lease considered active. Server-side statement_timeout does not bound client network wait; server idle-in-transaction timeout can release the lock while the transfer still emits chunks. Executor is adding a stale-heartbeat deadline, a 1.5s client timeout against a 5s server timeout, and a TCP blackhole test.
- Coverage gap: /web and /ui native Git readers are not covered, including repo overview/tree/blob/commit/diff/compare routes. Additional uncovered canonical repo reads found: CI dependency scanning before origin materialization; workspace source clone; namespace mount validation/view clone/changeset object validation; pull ref/object reads; and sharding source bundle/fsck. Offline backup requires service and Git descendants to be stopped. Executor is wiring the missing read paths and doing a broader search.
- No production caller of read_leases::exclusive() exists at this revision. Physical GC remains disabled in storage lifecycle; native transfer evidence proves PostgreSQL advisory-lock exclusion with a direct SQL probe, not an actual GC execution. Treat any GC protection claim as a future contract until an exclusive production caller and destructive integration test exist.

Review remains open pending executor fixes and native re-review.
