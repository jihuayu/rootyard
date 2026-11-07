# Round 5 priority work: measured progress, acceptance still open

The current measured candidate is commit `8054fea1c77465fc466eaaf6866fcf58e803283f`, compiled with Rust 1.99.1 and `pando-lab`. Its binary SHA-256 is `9fb0ebea0f06d5e6de890acb2f5c2484b6f33324325a7e4fadb64c5859deb335`; the [build receipt](round5-evidence/candidate-build.json) records the compiled input digest. The baseline is `d689bf8062a73cfadbc0a72abf3f1546d992e09c`, binary `216585161cf8e70394b23d5079f282769805667349486daeab2ac95d023a3fed`. Later changes need their own final build and acceptance.

DeepSeek implemented the product patches; independent Luna Max reviews identified follow-up corrections. No issue is closed by this progress record.

The LFS experiment uses actual Rust processes, PostgreSQL 17.11 and Garage 2.1.0 on one shared host, with an owned counting proxy and a random 8 MiB object. [Raw baseline measurements](round5-evidence/lfs-baseline.json) and [raw candidate measurements](round5-evidence/lfs-candidate.json) include every latency sample, process read/storage byte counts, CPU ticks, memory observations and service-owned PostgreSQL connection samples. The portable harness is [tests/lfs_process_metrics.py](../../tests/lfs_process_metrics.py).

| Clients | Phase | Process rchar / served bytes, baseline → candidate | Candidate remote requests | Candidate P95 / P99 seconds | Candidate CPU seconds |
| --- | --- | --- | --- | --- | --- |
| 1 | restart_existing_local_empty_cache | 3.0000 → 2.0000 | {} | 0.301 / 0.301 | 0.26 |
| 1 | warm_batch_get | 3.0000 → 1.0000 | {} | 0.075 / 0.082 | 0.76 |
| 1 | remote_cold_batch_get | 4.0000 → 1.0000 | {'HEAD': 1, 'GET': 1} | 0.313 / 0.313 | 0.23 |
| 4 | restart_existing_local_empty_cache | 3.0000 → 1.2500 | {} | 0.316 / 0.316 | 0.34 |
| 4 | warm_batch_get | 3.0000 → 1.0000 | {} | 0.185 / 0.187 | 1.06 |
| 4 | remote_cold_batch_get | 4.0000 → 1.0000 | {'HEAD': 1, 'GET': 1} | 0.403 / 0.403 | 0.33 |
| 16 | restart_existing_local_empty_cache | 3.0000 → 1.0625 | {} | 0.627 / 0.627 | 0.64 |
| 16 | warm_batch_get | 3.0000 → 1.0000 | {} | 0.312 / 0.317 | 0.77 |
| 16 | remote_cold_batch_get | 4.0000 → 1.0000 | {'HEAD': 1, 'GET': 1} | 0.670 / 0.670 | 0.61 |

`rchar` is the kernel's process-wide read-syscall accounting, including reads beyond file digest input; it does not count all socket receive operations. `read_bytes`/`write_bytes` are kernel storage accounting, often zero with page cache. CPU is the service process including its threads, excluding PostgreSQL/Garage. Connection samples distinguish physical service connections and active SQL; checked-out idle clients and pool waiters are not instrumented yet. These samples are not exact busy-pool occupancy. Cold sample counts are small; empirical P95/P99 and shared-host debug-build timings imply no production SLA. Baseline and candidate runs had different concurrent host activity; compare raw counts and invariants before interpreting timing differences.

The same candidate passed the full LFS suite with and without a remote endpoint, actual Garage hydration/failure/retry/cancellation acceptance, the browser session suite, real Chromium browser flow, organizations, members, and the stock Git/JGit/libgit2 client matrix. Corrupted local bytes are rejected without a usable remote; with a valid remote, recovery must return the original body. Verification singleflight unit tests passed in the implementation worktree; full integrated Rust gates remain to be run after lint corrections.

The [workspace slow-read baseline](round5-evidence/workspace-baseline.json) timed out a one-second health check and blocked a 500 ms row-lock attempt. The [workspace candidate](round5-evidence/workspace-candidate.json), compiled at `fef27f9` before later integration, answered health in 1.6 ms and allowed the row lock while the actual scan read was held. An LD_PRELOAD gate holds only an owned fixture file; this simulates a slow read, not a physical disk failure. Four of five new native capture cases passed. The stale-revision test injected an event gap and then incorrectly expected normal event replay; its report also failed after unittest consumed its suite. Both test defects are tracked for correction; this is not a passing full-suite claim.

The [webhook baseline](round5-evidence/webhook-baseline.json) did not reach the healthy receiver while an earlier sorted repository was held. The [candidate](round5-evidence/webhook-candidate.json) reached it while the slow receiver remained held, without manual dispatch. The larger new fairness/PR scripts failed during duplicate Git fixture initialization before their assertions and need correction and rerun.

Remaining review gates include bounded webhook backfill fanout, workspace Git mutation ownership through disconnect and graceful shutdown, full fmt/Clippy/unit/native acceptance on the final integrated commit, and exact DB-pool instrumentation. The unsafe deferred workspace baseline protocol and unrelated asynchronous checkpoint-copy change were removed. Existing API-side baseline hashing/checkpoint copy costs remain documented follow-up work. Physical cross-host fencing and power-loss acceptance for #26/#43/#44 still need their required independent hardware environment.
