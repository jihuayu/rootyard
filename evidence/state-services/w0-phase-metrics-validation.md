# W0 phase measurement increment

Accepted report: `w0-native-phase-metrics-v5.json`. The default-disabled
`state-baseline-metrics` feature records twelve fixed phases through the
existing private metrics listener. Concurrent requests are bracketed once per
whole batch, with individual wall times separately labelled as unattributed.
Unexpected missing deltas fail capture; HTTP redirects are refused.

Validation:
- Ten feature-enabled Rust phase tests passed; default library check passed.
- Twelve build-receipt tests and 22 runner/parser/accounting tests passed.
- The exact feature-enabled native binary passed all 32 final workload cases
  against real loopback PostgreSQL, S3-compatible Garage and Vault fixtures.
  Of these, 26 captured phase deltas, four were expected setup/GitFS/start
  lifecycle cases and two were offline cutovers. No requested delta was missing.
- 157 PG samples observed a peak of 15 API-owned connections, zero sampled lock
  waiters and no sampler errors. Sampling can miss short waits.
- Scrape overhead was 10.449 ms median / 23.357 ms maximum; each scrape performs
  an additional SQL snapshot outside operation spans.

Across non-overlapping case/batch deltas, Git preparation recorded 250 observations
/ 18.672 seconds, hydration 203 / 9.757 seconds, fsck 50 / 4.684 seconds, and ref
advisory acquisition 19 / 1.667 seconds. These phase spans themselves are nested:
do not add them or subtract their sum from elapsed runtime. SQL spans include
query submission/server execution/row return, not just lock wait. Successful
remote payload counters recorded 2,392,025 bytes each for upload and separate
verified read-back, and 7,438,566 bytes for GET. Retries/headers/partial failures
are excluded.

The same-ref batch observed one successful push and one HTTP409 response,
with the winner read back. It records `git_ref_rejected=0`, `http_conflicts=1`.
HTTP409 does not establish a particular application cause or an explicit-old-OID
CAS proof. Git report-status handling and synchronized race/atomic rejection
qualification remain open in #126 / #106 / #123.

Historical v1 retains 41 passing functional workload cases, but its overlapping
concurrent phase deltas and previous summed phase totals are invalid for individual
or batch attribution. They are superseded by v5 and must not be used as costs.
Local v2/v3 strict-rejection runs failed on the actual HTTP409; v4 passed before
the final mixed-diagnostic/partial-status hardening. No failed run is counted as
accepted qualification.

The host was shared, payloads small, and root-package debug symbols disabled.
No production budgets, exact CPU/temp-space costs, physical two-host behavior,
new architecture benefit or power-loss/HA qualification is established.
