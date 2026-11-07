# Round-3 issue #25 acceptance — migration / CI sidecar handoff

**Verdict:** `ACCEPT_FOR_DOCUMENTED_MODE`, **`closable_25 = true`**, 0 P1 and 3
inherited non-blocking P2. Issue #25 is **eligible to close after the primary's
final publication review and merge** of the docs/evidence change; the primary's
#25 PR follows PR [#62](https://github.com/jihuayu/rootyard/pull/62) (HA profile,
closes no issue). #26, #43, #44 and roadmap #48 remain open.

**Source/binary/harness:** compiled production source
`cb8d1b915a3c1e12990c038b7a43e2b7e891ff5f`, harness and reviewed worktree HEAD
`9f85c5adb4e1cfef5c114adbaceb2e74213f34ac`, production input
`0f865a04763c5be077e15151143554b191f8ad8a84462f6746d045eabea3bc90` (331 files,
recomputed unchanged at `9f85c5a`), immutable local binary
`157748addd3ad1cc67e9aa5fc2c60b76b524de4f6a09ae65bedfdea26f17958f`.

**Actual runs — all passed:** main jobs `sidecar-crash`, `migration`,
`takeover`, `partition` exit 0; extra jobs `rust-lib` (145 passed),
`rust-pando` (1 passed against real S3/Vault), `schema` (version 132) and the
exact `migration-phases` harness (5/5 genuine SIGKILL cases, all
`process_returncode = -9`, harness `64dd92d7…`) exit 0.

## Accepted mode

One trusted Linux host, separate Rust nodes with disjoint volumes, one
PostgreSQL authority, local process-session fence. No physical cross-host
storage fence, PostgreSQL HA/promotion, hardware power-loss or scalability
claim. #26 physical cross-host fencing remains unqualified.

- The old source after takeover is fenced read-only with unchanged old-volume
  bytes, while supported ingress may still proxy and ACK
  (`retired_source_push_supported_proxy_ack=true`,
  `retired_source_push_directly_rejected=false`); no claim that every old URL
  rejects.
- No forged SQL route or replica readiness (`simulated_fields=false`).
- The historical old 16 MiB takeover generic `409 replica rejected snapshot
  transfer` remains **UNCLASSIFIED**. The retained failed artifact is
  `attempts/pre-second-review-takeover-409/` (harness `f9ea54f…`, binary
  `c564ba14…`); no failed takeover JSON report hash was retained. Later passes
  are not proof of a fix and no causal fix is claimed.
- `13` registered sidecar hooks is not `13` SIGKILLs: 10 logical phases are
  recorded actual, PAUSE is used for concurrency-intersection probes, and the
  residual harness adds 5 genuine SIGKILL cases. The 34-row reconcile fixture
  is metadata-only.
- Deliberate fail-closed cap: 1024 CI pin intents / 2 MiB per repository across
  generations; no capacity or scalability claim.

## Inherited non-blocking P2

1. `handoff_pending` receipt-existence check; lost live evidence can re-open a
   409 path and missing/corrupt staging becomes a permanent 503 (fail-closed,
   operator-visible).
2. Release + re-pin of the same job id after restart returns 409
   `published CI sidecar file is missing` (replay/startup verification only;
   publication data correct).
3. Unknown orphan sidecar staging is retained forever with no quarantine,
   audit signal or observability (deliberate retain-on-unknown; disk growth).

## Evidence

Permanent bundle:
[round3/migration25-ci-handoff-cb8d1b9](../../evidence/round3/migration25-ci-handoff-cb8d1b9/README.md)
with full source map, main/extra status and certificate, four main reports, the
five-phase extra report, three stdout logs, source and final acceptance reviews,
manifest hashes, and the retained pre-fix failed takeover attempt. This
publication pass changes docs/evidence only: no runtime, schema, test, build or
native re-run was performed, and no issue is closed by this change alone.
