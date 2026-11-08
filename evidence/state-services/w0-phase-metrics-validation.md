# W0 phase measurement increment

The default-disabled `state-baseline-metrics` feature instruments twelve fixed
phases and exposes them only through the existing private metrics listener.
The checked-in runner captures per-case deltas, distinguishes process restarts,
bounds exposition reads, rejects inconsistent/missing samples, and records scrape
overhead. This is an increment toward #106 under #105, not completed RefStore,
Blob, deployment or capacity qualification.

Validation:
- Ten feature-enabled Rust phase tests passed; the default library check passed.
- Twelve native build-receipt tests and eleven runner/parser tests passed.
- The exact feature-enabled native binary passed all 41 workload cases against
  real loopback PostgreSQL, S3-compatible Garage and Vault fixtures. Its complete
  build receipt, source/binary hashes, runner hash, workload and per-case metrics
  are in `w0-native-phase-metrics-v1.json`.
- 157 PostgreSQL samples observed a peak of 15 API-owned connections and zero
  sampled lock waiters. Sampling can miss short waits; this is not zero contention.
- Scrape overhead was 12.222 ms median / 38.380 ms maximum. Each scrape executes
  an additional SQL snapshot outside operation spans.

Across captured case deltas, native Git preparation recorded 443 observations /
37.110 seconds, hydration 425 / 21.936 seconds, fsck 105 / 10.577 seconds, and ref
advisory acquisition 46 / 1.645 seconds. These are nested, aggregate spans:
do not add them, subtract them from total runtime, or interpret them as pure
server lock time. Successful remote payload counters recorded 3,190,915 bytes
for upload and separate verified read-back, and 14,087,974 bytes for ordinary
GET. Retries, headers and failed partial transfers are excluded.

The host was shared, the object/workload size was small, and the build explicitly
disabled root-package debug symbols. No production latency budget, exact Git CPU
cost, physical two-host behavior, or new architecture benefit is established.
The existing ordinary competing Git-push case is not a synchronized explicit
old-OID CAS proof; the positive atomic multi-ref case is not rejection-atomicity
qualification. Those #106 gates remain open.
