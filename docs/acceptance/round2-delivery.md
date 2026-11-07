# Round-2 final integrated delivery (`f319100`)

Status: **FINAL for all cells except the single physical-GC receipt marked
PENDING below.** Final production source is
`f31910086acbaa87d9e98df440ca8c28c7bb7e08` (one-line freeze of format-7
versions `<=131` beyond `340e668`), certified input digest
`fdfbbfcfe3acc36e5315e7dcc679d39709856c8c8fddf9aa32f8822b90c2ef5b`, immutable
binary SHA-256
`35d01c5f454bd8ea505a639e6a85ad5b90193f996451daa1a4d598c8e5dd0153`.

- Merged main: `5fa48544b2830423d25ae3087d0be6b7ab14867f`; [PR #56](https://github.com/jihuayu/rootyard/pull/56) is already merged.
- Historical `6d2f0b8` audit: [`main-6d2f0b8-audit.md`](main-6d2f0b8-audit.md). It is history, not current status.
- Final report set (the coordinator commits the exact report bytes):
  [`evidence/round2/integration-f319100/`](../../evidence/round2/integration-f319100/).
  Planned files are `core-verification.json`, `operations-verification.json`,
  `artifact.json`, `manifest.json`, `core/*.json` (canonical native names),
  `operations/cluster-*.json` and `reviews/*.json`.
- Environment limits: one Linux host, loopback, local PostgreSQL/Kafka, no
  external cloud identity, no second physical host, no delegated cgroup v2
  subtree.

## Actual verified results on binary `35d01`

| Area | Result |
| --- | --- |
| Rust unit/integration | 139 library tests + 1 Rust Pando test passed. |
| SHA-256 service | 2/2 passed. |
| SHA-256 matrix | 6/6 passed, including stock Git Forge pull/review/check/merge, 64-hex OID mirror plan/receipt, SHA-1 regression and mixed/abbreviated/zero-width negatives. |
| SHA-256 restore | 2/2 passed. |
| True legacy migration | 3/3 passed from a genuine format-6 archive produced by the old `6135` binary. |
| Schema contract | 8 checks passed, including public and custom bootstrap paths. |
| CI checkout | 15/15 passed. A retry with a new own database also passed 15/15; the initial shared-database migration/advisory-lock collision is preserved in the record as an environment artifact, not a product pass. |
| Sandbox | Real dev/CI 6/6 passed on a retry with its own database. The initial shared-database attempt is unqualified due to `information_schema` count 3-vs-1 and lock timeout, and is not counted. |
| GitFS maintenance | Lifecycle 3/3 and API 7/7 passed. |
| Pando maintenance | Automatic 2/2 passed, including cache tamper and non-ref OID survival across compaction rollback. |
| Pando backup | Optional paired active backup/restore in format 7 passed on the same Garage/Vault; not a cross-store disaster-recovery claim. |
| Operations | All ten scripts passed; 9 gate-valid, migration extra passed, and 5 fake-evidence negatives were rejected. Aggregate gate: #44 `passed_local_single_host`, #43 `blocked_external_ha_and_source_fence`, `production_scope=not_certified`. |
| Physical GitFS GC | **PENDING.** The original combined eight-case run stopped at the ENOSPC projection wait with the first four cases passed. Test-only fix `47a93ed` (maint23) synchronizes live projection/ref-index delivery before stop and bounds namespace-view 503 retries to 20; reviewer APPROVE with no P1/P2 at `review_data/physical-fixture47-review.json`. The full patched eight-case native run is in progress. This is the only remaining PENDING cell. The patch changes tests only; production input digest is unchanged, so the `f319`/`35d01` certificate remains valid. |

Raw final-core logs are under the coordinator scratch
`verify_final_core/postprocess*` (original reports plus a new combined report
pending only the physical case); `verify_final_ops/report.json` is final and
completed.

## Selected issue mapping

| Issue | State | Verified | Remaining gap |
| --- | --- | --- | --- |
| #38 SHA-256 | **CLOSE after final PR merge** | Service 2/2, matrix 6/6 (Forge pull/review/check/merge with stock Git, mirror plan/receipt 64-hex, SHA-1 and mixed negatives), restore 2/2, true legacy-130 3/3, schema contract 8 checks, CI checkout 15/15 on `35d01`. | None for the stated acceptance; close after the final PR merges. |
| #23 maintenance | **OPEN** | GitFS lifecycle 3/3, API 7/7; automatic Pando 2/2 with cache tamper and non-ref rollback; paired format-7 backup/restore same-store. | Remote Pando mark/delete/pruning remains DISABLED pending a foundational global-retention design. GitFS physical GC is complete only within its proven mode; the exact combined receipt is the single PENDING cell. |
| #25 migration | **OPEN** | Real draining reset, retired-source fencing before commit, online initial copy + delta, retained SQL roots, list/abort; migration, partition and full takeover passed. | Per-phase crash matrix and CI-sidecar intent/directory handoff with retained roots are unproven. |
| #26 controller | **OPEN** | Same-host session fencing: SIGSTOP/partition, ADMITTED fencing, old-writer denial, duplicate/restart single promotion. | Physical cross-host fencing is unqualified. |
| #43 deployment | **OPEN / blocked for production gate** | Real TLS/SCRAM, Kafka SASL_SSL role profiles, manual local PostgreSQL promotion, PITR and local workload passed; gate `blocked_external_ha_and_source_fence`. | External automatic PostgreSQL HA/DCS, cross-host source fence and fresh-deployment restore production gate remain unavailable. |
| #44 measurements | **OPEN** | Real local 1/2/4-node workload, negative controls, ENOSPC, PG promotion/PITR; gate `passed_local_single_host`, `production_scope=not_certified`, no simulated claim. | Physical production hardware/cross-host qualification is not certified. |
| #32 sandbox | **OPEN / blocked for kernel cgroup** | Six real dev/CI cases, tmpfs-only artifact pool, launch-failure cleanup. | Positive kernel cgroup enforcement is BLOCKED: no delegated cgroup v2 subtree, rootless Docker cgroup driver `none`, cgroupfs EPERM. |
| #48 roadmap | **OPEN umbrella** | Tracks the above; #38 may close after merge. | #30 is already CLOSED via PR #50. Do not mass-close #2–#19: historical PR #49 code does not equal new acceptance. |

## Evidence and non-claims

Committed reports will live under the reserved directory
`evidence/round2/integration-f319100/` with the layout above. Links here are
relative and will resolve once the coordinator copies the exact report bytes;
no file in that directory is claimed before then.

- The certificate binds source `f319100`, input
  `fdfbbfc…` and immutable binary `35d01…`. The later physical-fixture patch is
  test-only and does not change the production input digest.
- `6831` and `ee02` are old binary/input hashes, not source commits.
- Cross-host physical fencing, external automatic PostgreSQL HA/DCS, cloud KMS,
  cross-datacenter partitions and production-scale endurance remain outside
  the demonstrated environment.
- The `6d2f0b8` audit and earlier `340e668` report references are historical and
  are not current final results.
