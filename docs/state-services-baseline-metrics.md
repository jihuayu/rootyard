# State-services baseline metrics (#106)

Opt-in, fixed-cardinality phase instrumentation used to produce #106 baseline
evidence for the Pando state services (ref publication, remote artifact
retention, snapshot materialisation, remote object transport). It is **not** a
correctness or authority mechanism: no lock, CAS, lease, deadline or liveness
guard changes because of it, no decision reads these values, and no phase
measurement can promote a failing operation to a successful one.

## Enabling and exposure

* Cargo feature `state-baseline-metrics`, default **OFF**, adds no dependency.
* OFF (default): call sites compile to a zero-sized inert timer. Nothing is
  recorded, allocated, formatted or exported, and the awaited futures are polled
  exactly as before. Behaviour and decisions are identical in both builds.
* ON: recording is a handful of saturating `AtomicU64` increments. Memory is
  constant: 12 phases x (3 outcomes + 11 histogram buckets + 3 scalars) per
  process. Nothing is written to PostgreSQL or to the object store.
* Exposition is appended by the **existing private loopback listener** in
  `src/metrics.rs` (`ROOTYARD_METRICS_BIND=127.0.0.1:<port>`, path `/metrics`).
  The application listener/router never exposes these series, and the listener
  stays unauthenticated loopback-only.
* Labels are fixed in code. No repository, user, ref, key, token, database URL,
  path or error-message value is ever used as a label, and there are no
  per-request label values, so cardinality cannot grow with load or tenants.
* Counters reset on process restart and saturate at `u64::MAX`.

## Truth boundary

Every value is produced by one process on one physical host for one run of one
workload. It describes the awaited client operations in that process only. It is
not a claim about another host, a replica, a client, a filesystem cache state or
a production fleet, and it is not a substitute for measuring the whole push or
cold/warm run: phase observations explain where a whole run spent time, they are
never a proxy total.

## Phases

The `phase` label set is closed (`rootyard_baseline_phase_*`):

| `phase` | What the awaited span actually covers | Call site |
| --- | --- | --- |
| `publication_slot` | Waiting for one of the four fixed publication guard slots | `storage/ref_publication.rs` |
| `ref_advisory` | Waiting for the sorted exact-ref advisory locks plus the owner session that holds them (includes that session's unmetered pool checkout and the bounded retry sleeps) | `storage/ref_publication.rs` |
| `repo_publication_window` | Requesting and receiving the repository-wide window grant, which is served on the existing owner session (no extra pool checkout) | `storage/ref_publication.rs` |
| `pool_checkout` | Waiting for a pooled PostgreSQL connection at these instrumented call sites only: `pando_gateway::publish`, `snapshot::materialize` (two), and `pack_store` publish (two), manifest load and recover | `pando_gateway/publish.rs`, `snapshot.rs`, `pack_store.rs` |
| `state_row` | Full client round trip of the `pando_repository_states` `SELECT ... FOR UPDATE OF s`: submission, PostgreSQL execution, row-lock wait, row return | `pando_gateway/publish.rs` |
| `authority_lock` | Full client round trip of the singleton storage-authority `SELECT ... FOR UPDATE`: submission, execution, row-lock wait, row return | `pando_gateway/retention.rs` |
| `native_git_prepare` | `git init --bare`, per-ref `update-ref`, `symbolic-ref HEAD` | `pando_gateway/snapshot.rs` |
| `native_git_fsck` | `git fsck --full --strict` over the reconstructed snapshot | `pando_gateway/snapshot.rs` |
| `native_git_hydration` | Recovering one declared pack into the disposable snapshot (cache copy, or remote recovery plus decrypt) | `pando_gateway/snapshot.rs` |
| `remote_put` | One **S3-backed** object upload of a known source length | `storage/remote_objects.rs` |
| `remote_verified_readback` | Post-upload read-back verification of a known object length, **S3-backed** | `storage/remote_objects.rs` |
| `remote_get` | Whole-object GET into a local destination, **S3-backed** | `storage/remote_objects.rs` |

Only real await boundaries are timed. A phase starts immediately before the
awaited operation and ends when that operation completes, fails or is dropped.
No callback, protocol handler or lock scope is introduced, and no existing
future deadline or liveness guard is replaced: `native_git_*` phases are still
wrapped by the read-lease guard, and the publication phases still propagate
`unavailable()`/`Error` exactly as before.

`state_row` and `authority_lock` are **client round trips**, not pure lock waits:
they contain statement submission, PostgreSQL execution, the row-lock wait and
the row coming back. A large value therefore does not prove lock contention, and
a zero value does not prove an uncontended lock (the statement may simply not
have waited and PostgreSQL execution is included either way).

The `remote_*` phases are only produced by the S3-backed object store. When the
local-filesystem object store is configured, those three series stay at zero and
no local file I/O is disguised as remote transport; the local path keeps exactly
its previous behaviour and error handling.

## Outcomes

`outcome` is a second closed label set:

| `outcome` | Meaning |
| --- | --- |
| `ok` | The awaited operation completed successfully (`Ok`). |
| `error` | The awaited operation completed with an error (`Err`), **including** a nested `tokio::time::timeout`/`timeout_at` that expired and returned `Elapsed` to the instrumented future. |
| `cancelled` | The instrumented future or its timer was dropped before any completion could be observed: the caller was aborted, the enclosing future was dropped, or the task ended. No completion was observed. |

`cancelled` is deliberately narrow. It is not an application error and it is not
a deadline signal: a deadline that fires normally returns `Err(Elapsed)` inside
the future and is counted as `error`. A timer only starts when its future is
first polled, so a future dropped before it is polled records nothing at all.
After all recorded timers have drained, observations per phase equal `ok + error + cancelled`, and each timer
records at most once because an explicit finish marks it as recorded before the
`Drop` fallback runs.

## Duration histogram

`rootyard_baseline_phase_duration_seconds` is a Prometheus histogram over the
same wall-clock spans, with fixed cumulative bounds in seconds:
`0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 5, 30, +Inf`.

* The overflow bucket is `+Inf`, and, after timers drain, it equals
  `rootyard_baseline_phase_duration_seconds_count`.
* Buckets mix outcomes; use the outcome counters to separate them. A histogram
  per outcome would multiply cardinality, so it is deliberately not exported.
* `_sum` accumulates nanoseconds and saturates at `u64::MAX` (about 584 years),
  rendering as fixed-point seconds.
* Durations are wall clock, so they include scheduler delays and, for
  `native_git_*`, the subprocess time itself. They are not CPU measurements and
  make **no exact Git CPU claim**: git's internal CPU inside `receive-pack`,
  `fsck` and pack writing is not separately observable, and neither is
  PostgreSQL server execution separated from the client round trip, kernel
  socket time or DNS.

## Bytes

`rootyard_baseline_phase_bytes_total` counts only successful, S3-backed
transfers, and only bytes moved through a known stream or source length:

* `remote_put` and `remote_verified_readback` count the known object length after
  the transfer reports success.
* `remote_get` counts the bytes observed while streaming into the destination.
* A failed or cancelled transfer records `error`/`cancelled` with no bytes,
  because the transferred amount is unknown.
* These are **lower-bound logical-payload counts, never exact wire counts**.
  Headers, TLS framing and bytes re-sent by client retries or the local
  filesystem layer are not visible here, and they are not object-metadata sizes.

## Non-additivity, coverage and exclusions

Phase spans nest, so **summing phase durations is invalid** and no phase value
may be used as a total:

* `native_git_hydration` contains any remote GET and decryption performed
  underneath it, so `remote_get` and `native_git_hydration` overlap.
* `ref_advisory` contains its owner session's pool checkout, but that checkout is
  not separately recorded as `pool_checkout`; the label is used only at the call
  sites listed above.
* `remote_verified_readback` is recorded **instead of** `remote_get` for the same
  transfer (the code paths are split), so those two never double count.
* `repo_publication_window` uses the existing owner session, so it adds no
  `pool_checkout` observation of its own.

Measured boundaries are exactly the call sites in the phase table. Not measured,
and therefore excluded from any baseline claim:

* pool checkouts in admission, read-lease, ref-admission, authorization, event
  delivery, heartbeat workers and the metrics scrape itself — `pool_checkout`
  is not full server checkout coverage;
* native Git subprocess CPU and internal syscall breakdown beyond the coarse
  `native_git_*` spans (notably `receive-pack`/pack-objects work on the push
  path, which has no distinct instrumented boundary);
* in-process transient disk usage, including worst-case GC temp peaks — no
  bounded temp-directory high-water mark is sampled;
* waits on in-process mutexes (for example the local writer mutex inside
  `enter_window`), request/response body transport inside the Git HTTP layer,
  PostgreSQL server execution on its own, kernel socket time and DNS;
* ranged object GETs and every local-filesystem object operation;
* anything on another host, replica or client.

## Observer overhead of a scrape

`/metrics` itself acquires a pooled PostgreSQL connection and runs one SQL
snapshot statement per scrape, plus the in-process counter reads. That work sits
outside every instrumented span, but it shares the same pool and database being
measured, so a before/after scrape nudges the case slightly (one extra
connection checkout and one short query per scrape). Treat before/after
differences as lower-resolution than the counter deltas, and never read a zero
series as proof that a lock, checkout or database round trip was uncontended.

## Scrape protocol for a baseline case

Per case (a real PG + Garage + Vault workload on one host), scrape the loopback
endpoint immediately before and after the case with the same process id, and
subtract counter and histogram values. For each phase, the `count` delta must
equal the `ok + error + cancelled` deltas. Report the whole push and the whole
cold/warm run alongside; phase deltas explain that number, they do not replace
it, and they must never be added together.

## Runner capture (`--phase-metrics`)

`scripts/state_services_native_baseline.py` accepts an optional
`--phase-metrics` flag. Without it the runner, the environment it passes to the
binary and the report are byte-for-byte the previous behaviour: no exporter
bind, no scrape and no extra report keys. With it:

* the binary must be built with `--features state-baseline-metrics`; the runner
  sets `ROOTYARD_METRICS_BIND=127.0.0.1:<port>` where the port is an ephemeral
  loopback port allocated and released by the fixture. There is no endpoint
  argument, nothing external is contacted, and no secret is read.
* each **online** case is bracketed by one `/metrics` scrape before and one
  after; the report stores per-phase deltas of `observations`, the three
  outcomes, cumulative histogram buckets, `_sum`, `_count` and bytes.
* every sample carries the process identity `(pid, kernel starttime)`. Deltas are
  computed only within one identity: `h.stop()`/`h.start()` are wrapped to
  scrape the running process one last time before it is signalled and to reset
  the baseline afterwards, so a restart can never produce a negative or a
  cross-process delta. A case that reports `process_restarted` has no delta.
* the legacy GitFS seed pushes and the offline cutover CLI are recorded as
  `not_applicable`/`offline` with a reason instead of a fabricated zero delta,
  and no scrape is attempted while no application process is running.
* an exporter that answers but exports no `rootyard_baseline_*` series marks the
  report `feature_disabled`; an unreachable exporter marks it `unavailable`.
  Both are explicit errors because the flag was requested, and in neither case
  are zero values invented.
* the report records the measured scrape cost (`scrape_overhead_ms` median/max)
  because each scrape itself takes one pooled PostgreSQL connection and runs one
  SQL snapshot statement outside the instrumented spans, plus `phase_limits`
  and the per-process start/stop/final observation markers.
* **concurrent cases are bracketed once per batch.** Each `ThreadPoolExecutor`
  group (different-ref, cross-repo new pack, competing same-ref) is one
  `measure("…batch", run_all_futures)` case, so a batch produces exactly one
  before/after scrape pair. Workers never call `measure` or scrape. Per-push
  worker wall times are reported under `concurrent_wall_times` and are **not**
  phase attributed: the phase deltas belong to the whole batch and must never be
  divided, summed or compared per push.
* historical v1 reports that recorded one `measure()` per concurrent push have
  overlapping process-global counter deltas. Their per-case phase values are
  **invalid for individual or batch aggregation** and remain historical raw data
  only; the report carries this in `interpretation.historical_v1` and the root's
  v2 run supersedes them.
* the non-winning same-ref contender is accepted as a rejection only when its
  stderr shows a Git ref rejection (`[remote rejected]`, `[rejected]`,
  non-fast-forward, failed to update ref, stale info) and shows no auth or
  transport fault; otherwise the run fails. This is ordinary competing pushes,
  not an explicit-old-OID CAS assertion.
* the exporter is opened through a handler that **refuses redirects**: a 302/301
  raises instead of following a `Location` that could point outside loopback, so
  the private-origin claim holds even for a misbehaving listener.
* every scanned case carries a fixed `phase_metrics.status`, summarised in
  `phase_metrics.accounting`. `captured`, `not_applicable` (setup and process
  start lifecycle) and `offline` are anticipated; `service_stopped`,
  `process_restarted`, `unavailable` and `feature_disabled` are listed as
  `unexpected` and force the run status to `failed`, so a lost sample can never
  look like a clean pass. A case that loses process continuity also marks the
  capture `partial` and stops further scraping.

Report interpretation stays as above: `state_row`/`authority_lock` are client
round trips rather than exact SQL lock wait (still unmeasured), phase spans nest
and must never be summed, and bytes are logical payload of successful S3-backed
transfers only. `python3 -m unittest tests.test_state_services_native_baseline`
checks the parser and delta logic (valid cumulative input, unexpected labels and
series, non-finite/negative/fractional counters, inconsistent histograms,
restart vs regression, skipped/unavailable cases never scraping, the
one-bracket-per-batch structure, the status accounting, the same-ref rejection
diagnostic and the redirect refusal without external contact) without running
any native workload.

## Status

This module supplies phase instrumentation plus metric semantics only. #106
remains open until the root-owned measurement of real whole push/cold/warm runs,
frozen budgets and full coverage of the intended phases exist. Nothing here is a
performance claim, and the legacy
`evidence/state-services/w0-native-legacy-pando-v5.json` baseline is unchanged.

## Tests

`cargo test --features state-baseline-metrics baseline_metrics::tests` uses
private registries (the process-global one is written concurrently by other
library tests) and drives the production timer and timed helpers, covering:
explicit `ok`/`error`/drop separation, single recording after an explicit finish,
an `Err(Elapsed)` returned from inside the future counted as `error`, real
cancellation by dropping the instrumented future, no recording for a never-polled
future, exact concurrent counter totals after thread join, fixed
label/series cardinality, histogram bucket boundaries including the overflow
bucket, and bytes only on completion. The feature-OFF build is exercised by the
existing `metrics` tests, which assert the legacy 17 series are unchanged.

Live exposition reads independent relaxed atomic counters. A scrape racing a completed timer may contain a temporarily inconsistent observation/outcome/histogram snapshot. Equalities and per-case deltas require quiescent case boundaries; the strict runner rejects an inconsistent scrape rather than fabricating zero values. Histogram spans remain nested, and SQL timings include the complete query round trip.
