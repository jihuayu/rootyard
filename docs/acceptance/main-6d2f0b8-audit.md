# Main `6d2f0b8` acceptance audit (2026-11-07)

Scope: reconcile the merged state of pull requests #49-#55 against the
acceptance criteria of issues #23, #25, #26, #32, #38, #43, #44 and the #48
roadmap. This is an independent documentation audit, not a closure of any
issue.

- Audited source: `6d2f0b845525921339fa045868c2029d6dc42923` (`origin/main`).
- Audited binary: private build of that commit, SHA-256
  `6135f0288cdbfc6f072f1cb071a667bbef35496388385e6b9fb2ccb9be2b9869`.
- Environment: PostgreSQL 17.11 at the shared local test endpoint, stock Git
  2.52, isolated temporary repositories. No external cloud identity or second
  physical host was configured.
- Status vocabulary: **met** means an executed native result on the audited
  source/binary or a committed report binding an exact binary and topology;
  **unproven** means the implementation or a test exists but the audited
  current-main combination was not executed; **blocked** names a concrete
  unsatisfied dependency.

## Reconciled merges

| PR | Merge commit | Effect |
| --- | --- | --- |
| #49 | `43f21d8` | Integrated Forge/Web sessions, organizations, LFS locks, Workspace/Namespace, CI orchestration, local-process cluster fencing and paired recovery into main. |
| #50 | `3e69bb9` | Merged lazy Workspace VFS hydration (`src/workspaces/lazy.rs`) into main; the earlier ledger row still described it as an unmerged branch. |
| #51 | `4db394e` | Merged durable independent-ref admission/publication fencing, migration 126 and `tests/independent_refs.py`. |
| #52 | `1e8dc30` | Merged physical GitFS GC admission fencing, retention roots, quarantine, migration 127 and `tests/storage_lifecycle_physical.py`. |
| #53 | `6d2f0b8` | Merged the authenticated Pando gateway, two-phase GitFS↔Pando transition operator, encrypted pack CAS, transition backup wiring and SHA-1/SHA-256 transition service test. |
| #54 | `15fb769` | Merged SHA-256 Forge/OID-format admission and `tests/sha256_service.py`. |
| #55 | `0d34e37` | Merged the authorized maintenance-job observability API. |

## Issue audit

| Issue | Criterion | Status | Evidence on current main |
| --- | --- | --- | --- |
| #23 | Configured thresholds cause real maintenance without a manual lifecycle call | **met** | Current-main run: `python3 tests/storage_lifecycle.py --binary <private 6135f028>` -> 3/3 cases passed, including `scheduled_repack_and_staging` (automatic repack, commit-graph hydration, stale staging cleanup). |
| #23 | Worker death, duplicated wakeups and expired claims recover without overlapping destructive work or deleting retained objects | **met** | Same run: `expired_claim_reclaim` (duplicate active-kind rejected, late owner fenced, attempt/generation 2:2) and `killed_worker_volume_barrier` (SIGKILL server, descendant volume lock held, successor claimed attempt 2) passed against the audited binary. |
| #23 | Concurrent push/fetch/GC and backup/active snapshot preserve every retained reachable object | **unproven** | `tests/storage_lifecycle_physical.py` contains `physical_loose_packed_and_pin`, `backup_barrier_blocks_due_delete`, `active_fetch_snapshot_blocks_gc`, `active_push_publication_blocks_gc`, `enospc_pack_rewrite_recovers`, `unlink_crash_reconciles_intent`, `younger_unreachable_history_keeps_old_blob`, `namespace_source_oid_survives_branch_deletion`; not rerun in this audit. Pando job kinds remain reserved/rejected. |
| #25 | Migrate between disjoint volumes while clients write; destination serves acknowledged commits and passes fsck | **met** | `tests/cluster_migration_native.py`; committed report `evidence/cluster-migration-publication.json` (binary `678f815c…`, PG 17.11) and independent review `evidence/reviews/cluster-migration-lock-order-6972ac1-review.md`. |
| #25 | Empty/corrupt/partially copied/stale target cannot be marked ready or promoted | **met** | Same harness: partial-copy rejection before cutover, ahead-journal rejection preserving the target sentinel, foreign operation-UUID rejection without draining another repository. |
| #25 | Crash in each phase and recover from durable state; retained CI/backup/snapshot roots survive | **unproven** | Target-process restart/resume is covered; no native crash injection for drain/fence/cutover phases and no retained CI/backup/snapshot-root migration case. |
| #26 | SIGSTOP/partition the old primary with an admitted writer; new primary cannot acknowledge until storage is fenced | **unproven** | Prior committed reports `evidence/cluster-takeover-run.json` and `evidence/cluster-partition.json` bind binary `e0f475a5…` and pass this shape. A current-main controller post-promotion push returns 409; the fix is active and no current-main rerun exists. |
| #26 | Resume the old process after promotion and prove it cannot mutate authoritative data | **unproven** | Prior report records `old_writer_restart_blocked` and retired-volume write rejection on `e0f475a5…`; current-main rerun pending the controller fix. |
| #26 | Controller restart, duplicate takeover and unavailable fencing preserve one writer or read-only state | **unproven** | Prior report records controller restart, duplicate identity and unavailable fence directory cases on `e0f475a5…`; current-main rerun pending. Scope remains a single trusted host. |
| #32 | Two isolated tasks cannot read each other's writable state or platform credentials | **unproven** | `tests/test_sandbox_service.py` starts two bwrap dev-mode jobs, checks distinct workspace files, absence of a shared workspace file and cross-tenant log/artifact denial. Cgroup-mode artifact export and crash cleanup are under active fix; no cgroup-mode run exists. |
| #32 | Resource exhaustion, cancellation and runner crash leave a terminal result and reclaim processes/storage | **unproven** | Dev-mode cancel/timeout and startup recovery exist; aggregate cgroup CPU/memory/PID/disk exhaustion and crash-cleanup acceptance are missing (active runner32 work). |
| #32 | Authorized logs/artifacts and retry only under a new fenced attempt | **unproven** | `tests/test_ci_sandbox.py` covers signed CI attempt fencing, terminal, logs and cancel; cgroup artifact export is under fix. |
| #38 | Create SHA-256 repository through the service and use stock Git to push/fetch/browse/review/check/merge/mirror/pin/checkout/restore | **unproven** | `tests/sha256_service.py` covers create, stock push/clone/fsck, browse, ref CAS, pull/review/check/CI-pin/merge with 64-hex OIDs. Mirror, pin, checkout and restore are not exercised end-to-end; a SHA-256 CI checkout 503 defect is under active fix. |
| #38 | Complete CI plan/receipt carries the correct format and 64-hex target; checkout verifies fetched OID | **unproven** | Source carries `object_format` through `src/ci_pins`, `src/ci_checkouts` and `src/mirror`; `tests/ci_job_checkouts.py` exercises only `sha1`. Active sha38 work is adding this matrix. |
| #38 | SHA-1 regressions and negative mixed/abbreviated OID tests through actual binaries | **unproven** | `tests/sha256_service.py` rejects 40-hex prefixes on pull/review/check/pin/merge/ref-transaction; SHA-1 suites exist, but no current-main combined run was performed in this audit. |
| #43 | Bring up reference deployment from documented inputs and verify a real cross-node Git flow over encrypted authenticated dependencies | **met** | `deployment/local_cluster.py` + `docs/deployment/local-cluster.md`; `evidence/cluster-local-profile.json` (binary `02a4b3d5…`) records two Rust nodes/volumes, PostgreSQL 17 TLS `verify-full` + SCRAM-SHA-256, Kafka 4.4 SASL/PLAIN over TLS, matching push/clone/browse OIDs; independent review `evidence/reviews/cluster-local-profile-ffec1ed-c8406cb-review.md`. Single trusted host only. |
| #43 | Fail over PostgreSQL and a storage node under load without double writers or false acknowledgements | **unproven** | PostgreSQL streaming promotion and PITR were rerun locally on 2026-11-07 (reports `evidence/cluster-pg-streaming.json`, `evidence/cluster-pg-pitr.json`); storage takeover evidence exists separately. No combined under-load failover in the reference deployment, and the current controller post-promotion 409 is under fix. |
| #43 | Restore metadata and storage into a new deployment and verify commits, job revocation, permissions and workers before reopening writes | **unproven** | PITR/snapshot evidence verifies retained commits, token revocation and delegation rotation, but not a new deployment with workers and permissions exercised before write reopen. |
| #44 | Reports identify source/binary/tool/topology/dataset/workload/hardware/raw evidence; simulated fields cannot satisfy a gate | **met** | `tests/cluster_workload_native.py`; `evidence/cluster-workload-integration.json` binds source commit, binary, Git/PG versions, hardware, topology, dataset, raw per-operation ACK/OID/timing and marks the separate benchmark API `simulation_only`. |
| #44 | Physically remove a retained object or stop the node and show readiness/reachability assertions fail | **met** | Same report: `removed_object_negative_control` detects a missing pinned blob and fails native fsck; owner SIGKILL returns 502 and fails closed. `tests/cluster_disk_pressure_native.py` adds real ENOSPC rejection (`evidence/cluster-disk-pressure.json`). |
| #44 | Calculate RPO/RTO from actual acknowledged operations and observed recovery, not request-supplied measurements | **met** | Workload/partition reports derive RPO from acknowledged OIDs and measured RTO; `execute_dr_drill` now rejects simulated inputs with 409. Local 1/2/4-node workload was rerun on 2026-11-07. |
| #44 | Update readiness/implementation documents with real-run claims and explicit untested boundaries | **unproven** | `TEST_READY.md` labels historical model results and lists native limits; the delivery ledger and implementation-status are being reconciled in this change. Final readiness wording remains for the coordinator follow-up. |
| #48 | Roadmap remains the tracking issue; a child is checked only after real acceptance | **unproven / open** | All child issues remain open. This audit found no fully closed child: #23 criterion 3, #25 criterion 3, #26 current-main rerun, #32 cgroup acceptance, #38 CI checkout and #43/#44 remaining gates are still open. `#48` must remain open. |

## Executed in this audit

```
ROOTYARD_TEST_DATABASE_URL=postgres://…/round2_delivery48 \
  python3 tests/storage_lifecycle.py \
  --binary /workspace/scratch/rootyard-round2/delivery48/rootyard \
  --report /workspace/scratch/rootyard-round2/delivery48/storage_lifecycle-report.json
```

Outcome: `passed: true`, `3/3` cases, binary SHA-256
`6135f0288cdbfc6f072f1cb071a667bbef35496388385e6b9fb2ccb9be2b9869`.
This binds the #23 scheduler, claim-recovery and killed-worker cases to the
audited main commit.

## Not claimed

- No issue is closed by this document.
- No active round-2 worker result is treated as delivered: current fixes for
  SHA-256 CI checkout (503), controller post-promotion push (409) and sandbox
  cgroup artifact/crash cleanup are still in progress at the time of writing.
- Single-host process fencing, a single PostgreSQL authority, local loopback
  traffic and emulated ENOSPC are stated limits, not cross-host HA evidence.
- The committed physical-GC, migration, takeover, PITR/streaming and workload
  reports were produced against their recorded binary hashes; they are cited as
  historical evidence, not rerun wholesale here.
