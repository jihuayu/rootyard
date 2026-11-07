# Migration / CI sidecar handoff — issue #25 combined acceptance evidence (`cb8d1b9`, harness `9f85c5a`)

Permanent evidence for issue
[#25](https://github.com/jihuayu/rootyard/issues/25) after round-3
integration of durable shard-sidecar handoff with the current storage
authority. Independent source review is `bounded-approve` with **0 P1 / 3
inherited P2**; the independent final acceptance review is
`ACCEPT_FOR_DOCUMENTED_MODE` with **`closable_25 = true`**. The issue closes
only after the primary's final publication review and merge of this
docs/evidence change; this bundle does not close it by itself.

**Status: all eight current jobs passed** — four main native jobs (sidecar
crash matrix, migration, takeover, partition) and four extra jobs (Rust lib,
real S3/Vault Rust Pando, schema contract, exact five-phase SIGKILL harness).
The primary has created PR [#62](https://github.com/jihuayu/rootyard/pull/62)
for the HA deployment profile; it closes no issue. The #25 publication PR
follows. #26, #43, #44 and roadmap #48 remain **OPEN**; no physical
cross-host fence is claimed.

## Source, binary and harness identity

| Item | Value |
| --- | --- |
| Compiled production source | `cb8d1b915a3c1e12990c038b7a43e2b7e891ff5f` |
| Harness / reviewed worktree HEAD | `9f85c5adb4e1cfef5c114adbaceb2e74213f34ac` |
| Production input digest | `0f865a04763c5be077e15151143554b191f8ad8a84462f6746d045eabea3bc90` (331 files) |
| Immutable local binary | `157748addd3ad1cc67e9aa5fc2c60b76b524de4f6a09ae65bedfdea26f17958f` (278,933,112 bytes) |
| Source-input map | `source-inputs.json` / `source-inputs-after.json` (byte-identical); full 331-file map |
| Main status | `status/main-status.json` (state `passed`, all four jobs exit 0) |
| Extra status | `status/extra-status.json` (state `passed`, stage `complete`, all four jobs exit 0) |

The production input digest was recomputed on the current `9f85c5a` tree and
still equals `0f865a0…`; the only post-compile commits are test-only phase
fixtures/harness and main documentation/Pando publication evidence, so the
certified `cb8d1b9` binary remains mapped to the current production input.
All five harness SHA-256 values in the two status files match the files at
`9f85c5a` (`d69f7ffd…`, `fc812390…`, `b0222e89…`, `b5c2c80c…`,
`64dd92d7…`). No binary, PKI material, secret, environment file, backup set,
native volume or database data is stored here.

## Passing jobs and artifacts

| Job | Result | Evidence |
| --- | --- | --- |
| main `sidecar-crash` | `passed`, exit 0, 10 logical phases actual, 13 hooks registered, 5 unexercised listed | `reports/sidecar-crash.json` |
| main `migration` | `passed`, exit 0, online copy/delta, retained CI pin + backup roots, barrier | `reports/migration.json` |
| main `takeover` | `passed`, exit 0, SIGSTOP old writer + durable fence kill, fsck passed | `reports/takeover.json` |
| main `partition` | coordinator job exit 0 and all actual assertions true; report has **no top-level `result` field** (known presentation nit, not invented here) | `reports/partition.json` |
| extra `rust-lib` | stdout `145 passed; 0 failed` | `logs/rust-lib-1794028176.log` |
| extra `rust-pando` | stdout `1 passed; 0 failed` against real S3/Vault | `logs/rust-pando-1794028230.log` |
| extra `schema` | stdout schema version `132`, all contract checks true, 85 tables / 13 functions / 33 triggers | `logs/schema-1794028297.log` |
| extra `migration-phases` | `passed`, harness `64dd92d7…`, 5/5 actual cases, every `process_returncode = -9` | `reports/migration-phases.json` |

`rust-lib`, `rust-pando` and `schema` have no coordinator-generated JSON
report by design; their evidence is the actual stdout log plus `exit_code: 0`
in `status/extra-status.json`. The log hashes are re-computed and stored in
`manifest.json`; all other log bytes are preserved and the manifest stores post-normalization SHA-256 values (explicit trailing-blank-line normalization, nothing else changed).

## Honest accounting: hooks, phases, and the old 409

- `13` registered hooks in the sidecar matrix is **not** `13` SIGKILLs. The
  matrix records **10** logical states in `phases_actual`; its
  `...concurrent-fresh-pin` probes use PAUSE for a concurrency intersection,
  and crash/restart boundaries are covered separately. The exact residual-phase
  harness adds **5 genuine SIGKILL cases** on distinct real process PIDs. Its
  two takeover cases SIGSTOP the old source first so the real node lease
  expires, then SIGKILL the target controller (declared in the report limits).
- The 34-row reconcile fixture is **metadata-only** and is not phase proof.
- The historical old 16 MiB takeover generic `409 replica rejected snapshot
  transfer` remains **UNCLASSIFIED**. The only retained failed artifact is the
  takeover assertion log/status from harness `f9ea54f9…` on binary `c564ba14…`
  in `attempts/pre-second-review-takeover-409/`; no takeover JSON/report hash
  was retained (the coordinator recorded no `report_sha256`). Later four
  isolated passes and the current full matrix passes are **not** proof that
  this particular 409 is fixed, and no causal fix is claimed.
- Source review native statement preserved verbatim as written at review time:
  > "Native is only partially observed: migration25 4/4 passed on the 351 binary (so the prior 351-pending statement is historical), while the combo cb8d1b9 build is 3/4 with partition still running; the fe8 hook worker with 5 unexercised hooks is not qualified, the old takeover generic 409 remains unclassified, and physical cross-host is unqualified. #25 stays OPEN."
  That `3/4, partition running` state is historical; the final actual status
  now records partition exit 0 and the extra 5-phase harness passed. No old
  `351` binary result is used as proof for the current `157748add` binary.
- The source-review historical note that "351 native was pending" is kept as
  written; actual migration25 4/4 on `351` already superseded it, and the
  current `9f85c5a` harness passes are reported separately.

## What changed (accepted functionality)

- Durable CI intent and receipt staging bound to owner, repository, object
  format, operation, refs and generation, with `O_NOFOLLOW` staging.
- No held data-exclusive lock across self-RPC; merge of fresh acknowledged
  pins under a mutual-exclusive target barrier; `RENAME_EXCHANGE` with
  fallback recovery and a durable publication receipt.
- Unknown staging state stays fail-closed; reconcile operations are not
  limited to 32; generations `1..=source_generation` are retained through a
  real `0 -> 1 -> 0` migration while old grants are denied and a fresh
  generation-3 checkout works.
- Bounded 2 KiB success receipts and static status-only error classes: no peer
  body text is logged or returned. Three unit bounds passed inside the 145-test
  Rust lib run.
- Deliberate fixed fail-closed cap of 1024 CI pin intents / 2 MiB per
  repository across historical generations; **no capacity or scalability
  claim** beyond that limit.

## Accepted scope and remaining bounds

Accepted mode: **one trusted Linux host**, separate Rust nodes with disjoint
volumes, one PostgreSQL authority, and a local process-session fence. All #25
functional criteria ran in the actual native jobs per the final acceptance
review. Physical cross-host storage fencing (#26) is unqualified and remains
open; #43/#44 and roadmap #48 remain open physical/HA gates (PR #62 is the HA
profile PR, closing nothing). The old source URL after takeover may still be
supported by a proxy and ACK while the old volume is immutable and the writer
is fenced; this is not a claim that every old URL rejects. No hardware
power-loss, multi-zone, automatic PostgreSQL HA or production-scaling claim.

Inherited, documented, non-blocking P2s (preserved from independent review):
1. `handoff_pending` checks only receipt existence: lost live `ci-pins`
   evidence can re-open the old 409 path, and missing/corrupt staging becomes a
   permanent 503 (fail-closed, operator-visible stuck state).
2. Releasing and re-pinning the same job id after restart replays a legitimate
   receipt check as 409 `published CI sidecar file is missing` (publication
   data correct; replay/startup verification only).
3. Unknown orphan sidecar staging with no operation row is retained forever
   with no quarantine or audit/observability signal (deliberate retain-on-unknown;
   unbounded disk growth and no operator signal).

These are not hidden or converted into a hardware blocker.

## Reviews

- `reviews/source-review.json` — bounded source review of `799d45b` vs
  `351da69`, 0 remaining P1, 3 inherited P2, historical native status verbatim.
- `reviews/acceptance-review.json` — **final** independent acceptance review
  superseding `acceptance-review-pending`; `verdict =
  ACCEPT_FOR_DOCUMENTED_MODE`, `closable_25 = true`, 5/5 real SIGKILL phase
  cases, precise pause-vs-SIGKILL accounting, no forged SQL route or replica
  readiness.

## Manifest

`manifest.json` stores size + SHA-256 for every file in this bundle, the source
map digest/file count, job exit codes, and report case counts. It is generated
programmatically and must be regenerated if any bundle file changes.
