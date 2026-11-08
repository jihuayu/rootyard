# State-services baseline metrics (#106)

Opt-in, fixed-cardinality phase instrumentation used to produce #106 baseline
evidence for the Pando state services (ref publication, remote artifact
retention, snapshot materialisation, remote object transport). It is **not** an
optimisation or a correctness mechanism: no lock, CAS, lease, deadline or
liveness guard changes because of it, and no phase measurement can promote a
failing operation to a successful one.

## Enabling and exposure

* Cargo feature `state-baseline-metrics`, default **OFF**, adds no dependency.
* OFF (default): call sites compile to a zero-sized inert timer. Nothing is
  recorded, allocated, formatted or exported; the bytes of awaited futures are
  polled exactly as before.
* ON: recording is a handful of `AtomicU64` increments with saturation. Memory
  is constant: 12 phases x (3 outcomes + 11 histogram buckets + 2 scalars).
* Exposition is appended by the **existing private loopback listener** in
  `src/metrics.rs` (`ROOTYARD_METRICS_BIND=127.0.0.1:<port>`, path `/metrics`).
  The application listener/router never exposes these series, and the listener
  remains unauthenticated loopback-only.
* Labels are fixed in code. No repository, user, ref, key, token, database URL,
  path or error-message value is ever used as a label; there are no per-request
  label values, so cardinality cannot grow with load or tenant count.
* Counters reset on process restart and saturate at `u64::MAX`.

## Truth boundary

Every value is produced by one process on one physical host for one run of one
workload. It describes the awaited operations in that process only. It is not a
claim about another host, a replica, a client, a filesystem cache state or a
production fleet, and it is not a substitute for measuring the whole push or
cold/warm run: phase observations are supporting evidence for where a whole-run
observation spent time, never a proxy total.

## Phases

The label set `phase` is closed (`rootyard_baseline_phase_*`):

| `phase` | What the awaited span covers | Call site |
| --- | --- | --- |
| `publication_slot` | Waiting for one of the four fixed publication guard slots | `storage/ref_publication.rs` |
| `ref_advisory` | Waiting for the sorted exact-ref advisory locks plus the owner session that holds them (includes bounded retry sleeps) | `storage/ref_publication.rs` |
| `repo_publication_window` | Requesting and receiving the repository-wide publication window grant | `storage/ref_publication.rs` |
| `pool_checkout` | Waiting for a pooled PostgreSQL connection inside the Pando publish/snapshot paths | `pando_gateway/publish.rs`, `snapshot.rs`, `pack_store.rs` |
| `state_row` | Waiting for the authoritative `pando_repository_states` row lock (`FOR UPDATE OF s`) | `pando_gateway/publish.rs` |
| `authority_lock` | Waiting for the singleton storage-authority row lock that serialises remote artifact reservations | `pando_gateway/retention.rs` |
| `native_git_prepare` | `git init --bare`, per-ref `update-ref`, `symbolic-ref HEAD` | `pando_gateway/snapshot.rs` |
| `native_git_fsck` | `git fsck --full --strict` over the reconstructed snapshot | `pando_gateway/snapshot.rs` |
| `native_git_hydration` | Recovering one declared pack into the disposable snapshot (cache copy, or remote recovery plus decrypt) | `pando_gateway/snapshot.rs` |
| `remote_put` | One object upload of a known source length | `storage/remote_objects.rs` |
| `remote_verified_readback` | Post-upload read-back verification of a known object length | `storage/remote_objects.rs` |
| `remote_get` | Whole-object GET into a local destination | `storage/remote_objects.rs` |

Only real await boundaries are timed. A phase starts immediately before the
awaited operation and ends when that operation completes, fails or is dropped.
No callback, protocol handler or lock scope is introduced, and no existing
future deadline or liveness guard is replaced: `NativeGit*` phases are still
wrapped by the read-lease guard, and the publication phases still propagate
`unavailable()`/`Error` exactly as before.

## Outcomes

`outcome` is a second closed label set:

| `outcome` | Meaning |
| --- | --- |
| `ok` | The awaited operation completed successfully (`Ok`). |
| `error` | The awaited operation completed with an error (`Err`). |
| `cancelled` | The timer was dropped before completion: deadline elapsed, task cancelled, or the surrounding future dropped. The operation was abandoned, not completed. |

`cancelled` is deliberate: an abandoned await must never be reported as `ok`,
and must not be confused with an application error. Observations per phase
always equal `ok + error + cancelled`.

## Duration histogram

`rootyard_baseline_phase_duration_seconds` is a Prometheus histogram over the
same wall-clock spans, with fixed cumulative bounds in seconds:
`0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 5, 30, +Inf`.

* The overflow bucket is `+Inf`, and it always equals
  `rootyard_baseline_phase_duration_seconds_count`.
* Buckets mix outcomes; use the outcome counters to separate them. A histogram
  per outcome would multiply cardinality, so it is deliberately not exported.
* `_sum` accumulates nanoseconds and saturates at `u64::MAX` (about 584 years),
  rendering as fixed-point seconds.
* Durations are wall clock, so they include scheduler delays and, for
  `native_git_*`, the subprocess time itself. They are not CPU measurements and
  make **no exact Git CPU claim**: git's internal CPU inside `receive-pack`,
  `fsck` and pack writing is not separately observable, and neither is
  PostgreSQL server CPU, kernel socket time or DNS.

## Bytes

`rootyard_baseline_phase_bytes_total` counts only successful transfers, and only
bytes this process actually moved through a known stream or source length:

* `remote_put` and `remote_verified_readback` count the known object length after
  the transfer reports success.
* `remote_get` counts the bytes observed while streaming into the destination.
* A failed or cancelled transfer records `error`/`cancelled` with no bytes,
  because the transferred amount is unknown.
* These are **lower-bound wire accounting, never an exact network byte count**.
  Retries or re-sent bodies inside the HTTP client, TLS, or the local filesystem
  layer can duplicate bytes on the wire, and those duplicates are not visible
  here. They are also not object-metadata sizes.

## Non-additivity and exclusions

Phase spans are nested, so **summing phase durations is invalid** and no phase
value may be used as a total:

* `remote_verified_readback` performs an inner object GET on the same path;
  `native_git_hydration` contains any remote GET and decryption inside it.
* `repo_publication_window` and `ref_advisory` include `pool_checkout` waits of
  their owner sessions.

Not observable by these phases, and therefore excluded from any baseline claim:

* native Git subprocess CPU and internal syscall breakdown beyond the coarse
  `native_git_*` spans (notably `receive-pack`/pack-objects work on the push
  path, which has no distinct instrumented boundary);
* in-process transient disk usage, including worst-case GC temp peaks — no
  bounded temp-directory high-water mark is sampled;
* waits on in-process mutexes (for example the local writer mutex inside
  `enter_window`), request/response body transport inside the Git HTTP layer,
  PostgreSQL server execution time, kernel socket time and DNS;
* anything on another host, replica or client.

## Scrape protocol for a baseline case

Per case (a real PG + Garage + Vault workload on one host), scrape the loopback
endpoint immediately before and after the case with the same process id, and
subtract counter/histogram values. `count` deltas must equal
`ok + error + cancelled` deltas for the phase. Report the whole push and the
whole cold/warm run alongside; phase deltas explain that number, they do not
replace it.

## Status

This module supplies phase instrumentation plus metric semantics only. #106
remains open until the root-owned measurement of real whole push/cold/warm runs,
frozen budgets and full coverage of the intended phases exist; nothing here is a
performance claim, and the legacy `evidence/services/w0-native-legacy-pando-v4.json`
baseline is unchanged.

## Tests

`cargo test --features state-baseline-metrics baseline_metrics::tests` covers
outcome separation (including cancellation by an actually dropped future),
double-record prevention after an explicit finish, exact concurrent counter
totals after thread join, fixed label/series cardinality, histogram bucket
boundaries including the overflow bucket, and byte counting on completion only.
The feature-OFF build is exercised by the existing `metrics` tests, which assert
that the legacy 17 series are unchanged.
