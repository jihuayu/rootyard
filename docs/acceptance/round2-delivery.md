# Round-2 final integration delivery (candidate `340e668`)

Status: **FINAL INTEGRATION VERIFICATION PENDING.** This page records the
delivery boundary reached by the round-2 candidate on top of merged main
`5fa48544b2830423d25ae3087d0be6b7ab14867f`. It does not claim a combined final
PASS; cells marked PENDING are placeholders for reports the coordinator will
supply after the `verify_final_core` / `verify_final_ops` pipelines finish.

- Candidate source: `340e6681aef3b78a440dc1b0fc8a13ce497621ea`.
- Merged main before candidate: `5fa4854` (PR #56 already merged).
- Historical prior audit: [`main-6d2f0b8-audit.md`](main-6d2f0b8-audit.md)
  remains the record for `6d2f0b8`; it is not the current candidate status.
- Environment limits: one Linux host, local loopback, local PostgreSQL/Kafka,
  no external cloud identity, no second physical host, no delegated cgroup v2
  subtree.

## Candidate contents

| Area | Candidate commits | Boundary |
| --- | --- | --- |
| SHA-256 / backup | SHA-931, `d8540fc` | Format 7 / schema 131, immutable format 6 / schema 130, explicit `--allow-legacy-schema130` real upgrade and public/custom bootstrap. |
| Maintenance | `7cc01d0`, `d9eb6d9`, `7118521`, `32dfea8` | All-OID-preserving automatic Pando compaction, cache verification/anti-tamper, non-ref rollback; GitFS lifecycle/API/physical acceptance. |
| Cluster | `66abaf0`, `bcede68`, `73a673c` | Real draining reset, retired-volume fencing before takeover commit, online initial copy + delta, retained SQL roots, migration list/abort, promoted-owner inspection. |

PR #56 (`5fa4854`) already merged the certified runtime/operations source
`7a77c83`.

## Qualified individual evidence (not a combined final gate)

- **Runtime/operations (source `7a77c83`)**: committed reports under
  `evidence/round2/runtime-ops-7a77c83/` (`cluster-local-profile`,
  `cluster-tls`, `cluster-kafka-tls`, `cluster-pg-streaming`,
  `cluster-pg-pitr`, `cluster-disk-pressure`, `cluster-workload-integration`,
  `verification`) plus `evidence/round2/runtime-and-operations-review.json`
  (APPROVE). The gate reports `passed_local_single_host` and
  `production_scope=not_certified`.
- **Sandbox (source `960d615`)**: six real dev/CI native cases passed on
  certified inputs; committed summary is `evidence/round2/runner32-960d615.json`.
  Kernel cgroup enforcement remains blocked.
- **SHA-256 legacy restore (`d8540fc`, certified binary `8ef18…`, input
  `65c42…`)**: three real legacy schema-130 cases passed from an old archive
  produced at `6135`, without rewriting its manifest; no-flag rejection plus
  opt-in upgrade to 131; SHA-256 clone + pin/generation/grant revocation.
- **Maintenance (production-identical `FCC/bf6`)**: two automatic Pando cases
  passed, including cache tamper and non-ref OID survival across compaction
  rollback; GitFS lifecycle 3 + API 7 and physical 8 cases passed across the
  qualified chunks after the ENOSPC fixture fix.
- **Cluster (certified source `6831`, input `ee02`)**: migration and partition
  passed. Full takeover passed after the `73a673c` test corrected inspection
  of the new target after the old source was killed; receipt
  `cluster_finalizer/takeover-promoted-owner.json` is PENDING commit/citation.

## Selected issue mapping

| Issue | Proposed state | Verified now | Remaining gap |
| --- | --- | --- | --- |
| #38 SHA-256 | **open** | Legacy schema-130 3 cases, no-flag/opt-in upgrade, SHA-256 clone/pin/gen/grant revocation chunk. | Close only after one-source combined matrix: 6 SHA-256 + 2 restore + 3 legacy + schema 131 + 15 CI checkout cases. PENDING. |
| #23 maintenance | **open** | Automatic Pando compaction/cache/anti-tamper/non-ref cases; GitFS lifecycle 3, API 7, physical 8 within proven mode. | Remote Pando mark/delete/pruning remains disabled pending a global retention foundation. |
| #25 migration | **open** | Certified migration/partition; online copy+delta, retained SQL roots, list/abort, draining reset. | Per-phase crash matrix and CI-sidecar intent transfer with retained roots unproven. |
| #26 controller | **open** | Same-host session fencing: SIGSTOP/partition, ADMITTED fencing, old-writer denial, duplicate/restart single promotion. | Physical cross-host fencing unqualified. |
| #43 deployment | **open** | Real TLS/SCRAM, Kafka SASL_SSL role profiles, manual local PG promotion, PITR. | External automatic PG HA/DCS, cross-host source fence, fresh-deployment restore production gate blocked. |
| #44 measurements | **open** | Real local 1/2/4 workload and negative controls; gate only `passed_local_single_host`. | Physical cross-host/hardware qualification absent. |
| #32 sandbox | **open** | Six real dev/namespace cases; tmpfs-only artifact pool; launch-failure cleanup. | Positive kernel cgroup enforcement blocked (no delegated subtree / rootless Docker cgroup driver `none` / EPERM). |
| #48 roadmap | **open** | Umbrella tracking candidate progress. | Stays open while children are unfinished. Issue #30 is already CLOSED (PR #50); do not describe all children as open or unmerged. |

## Pending final evidence

The following are **not** existing files and must not be cited as results until
the coordinator supplies them:

- PENDING `verify_final_core` combined SHA-256/restore/legacy/CI matrix report.
- PENDING final maintenance combined report (GitFS + Pando within proven mode).
- PENDING final cluster crash/takeover reports and committed
  `cluster_finalizer/takeover-promoted-owner.json`.
- PENDING final sandbox dev/CI report and kernel-cgroup opt-in outcome.
- PENDING `verify_final_ops` regenerated `evidence/round2/runtime-ops-*` gate
  report with `passed_local_single_host` and `production_scope=not_certified`.

## Non-claims

- No issue is closed by this document. No combined final integration PASS is
  claimed.
- Cross-host physical fencing, external automatic PostgreSQL HA/DCS, cloud KMS,
  cross-datacenter network partitions and production-scale endurance remain
  outside the demonstrated environment.
- The `6d2f0b8` audit and its committed per-binary reports remain historical
  evidence, not current-candidate qualification.
