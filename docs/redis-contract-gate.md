# Owned real-Redis contract gate

The [hosted CI job](#ci-job) passed on the replica-promotion candidate.
The historical local report in
`evidence/state-services/cache-wake/redis-contract.json` records the earlier
owned Redis 7.4.2 fixture.

`scripts/check_redis_contract.py` is the reproducible optional gate for the
`state-redis` feature. It is intentionally independent of the ordinary verify
flow and never uses an inherited Redis endpoint.

## What the runner owns

- A private `0700` temporary directory, including a `0600` Redis configuration
  with a random ACL password and a rootyard task user; `default` is disabled.
- A finite `32 MiB` `allkeys-lru` cache with persistence disabled.
- An ephemeral CA and a server certificate with `IP:127.0.0.1` SAN. OpenSSL
  output is discarded so private key material is never printed.
- One official `redis:7.2.6-alpine` container, labelled with this process's nonce,
  directory, uid and name, running as the current uid:gid. Only the config and
  TLS files are mounted, read-only. The container binds `0.0.0.0` **inside** the
  container; Docker publishes only ephemeral `127.0.0.1` ports for 6379 and
  6380. The runner parses `docker port` and rejects non-loopback mappings.
- `ROOTYARD_TEST_REDIS_URL` and `SSL_CERT_FILE`/`SSL_CERT_DIR` are rebuilt for
  each child. Inherited Redis/trust variables are removed. The URL password is
  passed only through the child environment, never argv, logs or reports.
- Cleanup runs in `finally` even after a test failure and removes only the
  container id this process created. A label mismatch refuses removal. The
  runner never flushes or configures an external Redis and never changes host
  trust. If the Docker CLI times out or prints an invalid id after the daemon may
  have created the object, cleanup resolves only this run's random name, then
  proves the full id and every ownership label before removal; otherwise it
  keeps the private directory and reports cleanup unresolved.

## Prebuilt receipt and case contract

The runner consumes one explicit prebuilt `rootyard` lib-test executable and
its adjacent v1/v2 receipt. It does not run `cargo clean`, a Cargo build, a
compiler probe or any producer; invalid evidence is refused before the Redis
fixture is allocated. A v2 receipt must select the `rust-library-test`,
`profile.test` rootyard artifact with literal Cargo freshness (`true` or
`false`), exactly the state-redis build command (allowing only a trailing
`--jobs N`), the recorded command/features/profile, a support digest bound to
its full inventory, and matching original and relocated executable hashes.

The historical v1 path is accepted only when it actually records a lowercase
64-hex `lib_test_support_inputs_sha256` that matches the complete current
lib-test support closure recomputed with the original builder's file-only
algorithm. A v1 receipt that also carries a bound inventory must cover every
file in that closure rather than an arbitrary subset. Missing, malformed,
partial or changed support evidence is refused, as is any present top-level
`kind` other than `rust-library-test`; a weak historical receipt is reported
as failed, never counted as a pass. The v1 command shape, artifact fields and
absent freshness are read without rewriting the historical receipt.

The runner then runs the six ignored `real_redis_` cases with
`--test-threads=1` over plaintext loopback and again over verified private-CA
TLS, requiring exactly `6 passed; 0 failed; 0 ignored` in both runs. It next
runs the exact
`cache_wake::redis::tests::real_redis_cache_contract_round_trip_and_bounded_read`
case with an untrusted CA, requiring exactly one failure, then repeats that
exact case with the owned CA, requiring one pass. A zero-test, skipped-test or
unexpected-case run is a failure, never a false pass. Logs and the JSON report
are redacted before writing.

## CI job

`.github/workflows/redis-contract.yml` is a separate job with checkout, the
pinned Rust toolchain, native prerequisites used by the existing CI
(OpenSSL/FUSE/pkg-config/CMake/Clang), Rust caching, an explicit
`docker pull redis:7.2.6-alpine`, runner unit tests without Docker, all-target Clippy
with `state-redis` and denied warnings, the prebuilt build, the owned fixture
gate, and an always-uploaded report. The existing
`.github/workflows/ci.yml` verify flow is not changed.

Artifact `14690808966` records six passing plaintext cases, six passing TLS
cases, the expected untrusted-CA refusal, and a pass after restoring trust,
with zero skips. The Redis 7.2.6 run and build receipt bind to preview
`4d292b05f7c2b852ab55707ba62d056272eeb74f` and tree
`4cdd2d9675281a9d3a47e7fec26c330e7329cfcf`.
[Hosted Redis contract](https://github.com/jihuayu/rootyard/actions/runs/44864706589/job/136725683353)

Local invocation (requires Docker, OpenSSL and the official image; the
executable and receipt must already exist):

```sh
docker pull redis:7.2.6-alpine
python3 scripts/check_redis_contract.py \
  --executable /path/to/rootyard-lib-test \
  --build-receipt /path/to/rootyard-lib-test.build.json \
  --report test-results/state-redis/contract.json \
  --log-dir test-results/state-redis/logs
```

This remains a disposable single-host qualification. It does not prove HA,
Sentinel, Redis Cluster, production least-privilege ACLs, physical failure
behavior, production performance, or complete serving-cache consumer wiring
(#110). Redis remains advisory; PostgreSQL/RefStore remain authoritative.
