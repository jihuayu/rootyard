# Round-2 final integrated delivery (`f319100`)

Status: **FINAL — all native scope cells verified.** Final production source is
`f31910086acbaa87d9e98df440ca8c28c7bb7e08` (one-line freeze of format-7
versions `<=131` beyond `340e668`), certified input digest
`fdfbbfcfe3acc36e5315e7dcc679d39709856c8c8fddf9aa32f8822b90c2ef5b`, immutable
binary SHA-256
`35d01c5f454bd8ea505a639e6a85ad5b90193f996451daa1a4d598c8e5dd0153`.
Integration commit `36d05453b6903b501e0e0efa65e7422d81cc1ab5` merges the
final tests and commits the actual report set; production input digest remains
exactly `fdfbbfc…` from the `f319100` compiled source and `35d01` binary.

- Merged main: `5fa48544b2830423d25ae3087d0be6b7ab14867f`; [PR #56](https://github.com/jihuayu/rootyard/pull/56) is already merged.
- Historical `6d2f0b8` audit: [`main-6d2f0b8-audit.md`](main-6d2f0b8-audit.md). It is history, not current status.
- Committed final report set:
  [`evidence/round2/integration-f319100/`](../../evidence/round2/integration-f319100/).
  Files include `core-verification.json`, `operations-verification.json`,
  `artifact.json`, `manifest.json`, `core/*.json` (canonical native names),
  `operations/cluster-*.json` and `reviews/*.json`.
- Environment limits: one Linux host, loopback, local PostgreSQL/Kafka, no
  external cloud identity, no second physical host, no delegated cgroup v2
  subtree.

## Actual verified results on binary `35d01`

| Area | Result |
| --- | --- |
| Rust unit/integration | 139 library tests + 1 Rust Pando test passed. |
| SHA-256 service | 2/2 passed, including stock-Git Forge pull/review/check/merge format admission. Output: `core/sha256_service-output.json`. |
| SHA-256 matrix | 6/6 passed: mirror/pin/checkout, 64-hex OID plan/receipt, SHA-1 regression and mixed/abbreviated/zero-OID negatives. |
| SHA-256 restore | 2/2 passed. |
| True legacy migration | 3/3 passed from a genuine format-6 archive produced by the old `6135` binary. |
| Schema contract | 8 checks passed, including public and custom bootstrap paths. |
| CI checkout | 15/15 passed on an isolated own database. The failed first attempt (9 cases; shared-database migration/advisory-lock collision) is preserved unchanged in the history files; only the isolated retry is counted. |
| Sandbox | Real dev/CI 6/6 passed on a retry with its own database. The initial shared-database attempt is unqualified due to `information_schema` count 3-vs-1 and lock timeout, and is not counted. |
| GitFS maintenance | Lifecycle 3/3 and API 7/7 passed. |
| Pando maintenance | Automatic 2/2 passed, including cache tamper and non-ref OID survival across compaction rollback. |
| Pando backup | Optional paired active backup/restore in format 7 passed on the same Garage/Vault; not a cross-store disaster-recovery claim. |
| Operations | All ten scripts passed; 9 gate-valid, migration extra passed, and 5 fake-evidence negatives were rejected. Aggregate gate: #44 `passed_local_single_host`, #43 `blocked_external_ha_and_source_fence`, `production_scope=not_certified`. |
| Physical GitFS GC | **8/8 PASSED** on immutable `35d01` with reviewed test-only fix `ed8d074` atop `47a93ed`. First case now uses the supported HTTP branch delete plus reindex-delivery barrier; the scheduler is disabled only during fixture construction and re-enabled before GC assertions. Root cause was both offline branch-delete fixtures retaining valid SQL roots; production GC was correct. No production change. Receipt `physical_cold/report.json`, launch/test SHA `0dbb558e…`, reviewer APPROVE `physical_cold/review.json`. |

Raw final-core logs are under the coordinator scratch
`verify_final_core/postprocess*` (original reports plus a new combined report
pending only the physical case); `verify_final_ops/report.json` is final and
completed.

## Selected issue mapping

| Issue | State | Verified | Remaining gap |
| --- | --- | --- | --- |
| #38 SHA-256 | **CLOSE after final PR merge** | Service 2/2 including stock-Git Forge pull/review/check/merge; matrix 6/6 mirror/pin/checkout with 64-hex plan/receipt, SHA-1 and mixed/abbreviated/zero-OID negatives; restore 2/2; true legacy-130 3/3; schema contract 8 checks; CI checkout 15/15 on an isolated DB (failed first attempt preserved). | None for the stated acceptance; close after the final PR merges. |
| #23 maintenance | **OPEN** | GitFS lifecycle 3/3, API 7/7, physical GC 8/8 on `35d01`; automatic Pando 2/2 with cache tamper and non-ref rollback; paired format-7 backup/restore same-store. | Remote Pando mark/delete/pruning remains DISABLED pending a foundational global-retention design. GitFS physical GC is complete; the issue stays open only for the Pando foundation. |
| #25 migration | **OPEN** | Real draining reset, retired-source fencing before commit, online initial copy + delta, retained SQL roots, list/abort; migration, partition and full takeover passed. | Per-phase crash matrix and CI-sidecar intent/directory handoff with retained roots are unproven. |
| #26 controller | **OPEN** | Same-host session fencing: SIGSTOP/partition, ADMITTED fencing, old-writer denial, duplicate/restart single promotion. | Physical cross-host fencing is unqualified. |
| #43 deployment | **OPEN / blocked for production gate** | Real TLS/SCRAM, Kafka SASL_SSL role profiles, manual local PostgreSQL promotion, PITR and local workload passed; gate `blocked_external_ha_and_source_fence`. | External automatic PostgreSQL HA/DCS, cross-host source fence and fresh-deployment restore production gate remain unavailable. |
| #44 measurements | **OPEN** | Real local 1/2/4-node workload, negative controls, ENOSPC, PG promotion/PITR; gate `passed_local_single_host`, `production_scope=not_certified`, no simulated claim. | Physical production hardware/cross-host qualification is not certified. |
| #32 sandbox | **OPEN / blocked for kernel cgroup** | Six real dev/CI cases, tmpfs-only artifact pool, launch-failure cleanup. | Positive kernel cgroup enforcement is BLOCKED: no delegated cgroup v2 subtree, rootless Docker cgroup driver `none`, cgroupfs EPERM. |
| #48 roadmap | **OPEN umbrella** | Tracks the above; #38 may close after merge. | #30 is already CLOSED via PR #50. Do not mass-close #2–#19: historical PR #49 code does not equal new acceptance. |

## Evidence and non-claims

Committed reports are at
[`evidence/round2/integration-f319100/`](../../evidence/round2/integration-f319100/)
with `core-verification.json`, `operations-verification.json`, `artifact.json`,
`manifest.json`, `core/<native_name>.json` (service output is
`core/sha256_service-output.json`, schema output is
`core/schema_contract-output.json`), `operations/cluster-*.json` and
`reviews/*.json`. Links are relative to this page and resolve in the merged
main.

- The certificate binds source `f319100`, input
  `fdfbbfc…` and immutable binary `35d01…`. The later physical-fixture patch is
  test-only and does not change the production input digest.
- `6831` and `ee02` are old binary/input hashes, not source commits.
- Cross-host physical fencing, external automatic PostgreSQL HA/DCS, cloud KMS,
  cross-datacenter partitions and production-scale endurance remain outside
  the demonstrated environment.
- The `6d2f0b8` audit and earlier `340e668` report references are historical and
  are not current final results.
