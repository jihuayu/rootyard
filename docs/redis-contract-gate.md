# Owned real-Redis contract gate

Status: runner and separate CI job added; remote CI has **not** executed this job
in this worktree. This document makes no remote-PASSED claim. The existing local
root evidence in `evidence/state-services/cache-wake/redis-contract.json` is
from an earlier 7.4.2-owned fixture and remains the only executed evidence.

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

## Build and case contract

The runner performs `cargo clean --package rootyard` and then one
`cargo --config profile.dev.package.rootyard.debug=0 --config
profile.test.package.rootyard.debug=0 --config
profile.dev.package.rootyard.strip="debuginfo" --config
profile.test.package.rootyard.strip="debuginfo" test --locked --lib --features
state-redis --no-run --message-format=json-render-diagnostics`. Those config
flags apply only to this test build; the default deployable library profile is
unchanged. It requires a `Fresh=false`
`profile.test` library artifact with an executable, requires the build to
complete, records the actual command, `Cargo.lock` digest, source digest and
rustc version, and verifies the source digest did not change.

It then runs the six ignored `real_redis_` cases with `--test-threads=1` over
plaintext loopback and again over verified private-CA TLS, requiring exactly
`6 passed; 0 failed; 0 ignored` in both runs. It next runs the exact
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
with `state-redis` and denied warnings, the owned fixture gate, and an
always-uploaded report. The existing `.github/workflows/ci.yml` verify flow is
not changed.

Local invocation (requires Docker, OpenSSL, Cargo and the official image):

```sh
docker pull redis:7.2.6-alpine
python3 scripts/check_redis_contract.py \
  --report test-results/state-redis/contract.json \
  --log-dir test-results/state-redis/logs
```

This remains a disposable single-host qualification. It does not prove HA,
Sentinel, Redis Cluster, production least-privilege ACLs, physical failure
behavior, production performance, or complete serving-cache consumer wiring
(#110). Redis remains advisory; PostgreSQL/RefStore remain authoritative.
