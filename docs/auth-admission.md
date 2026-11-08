# Bounded authentication admission (partial issue #84)

This document describes a deliberately **partial** slice of issue #84. The
implemented slice bounds the browser login/token-exchange POST and the explicit
`GET /api/auth/whoami` identity lookup **before** either path may acquire a
PostgreSQL connection. It is not a complete authentication hardening feature.

## Explicit non-goals

The following are **not implemented** and are not claimed by this change:

- MFA, TOTP, WebAuthn or recovery codes;
- OIDC, OAuth authorization-code/device flows or an external identity provider;
- e-mail binding, e-mail verification or password reset;
- per-username/per-account lockout, progressive delays or CAPTCHA;
- distributed or cross-replica rate limiting;
- trusted-proxy parsing of `X-Forwarded-For`/`Forwarded`;
- persistent authentication audit records or credential storage changes.

The existing PAT/API-token, browser-session, CSRF and parent-token revocation
behaviour is unchanged. No plaintext token is persisted, logged or used as a
metric label.

## Source identity

The only source identity is the real TCP peer address supplied by Axum
`ConnectInfo`, injected by
`Router::into_make_service_with_connect_info::<SocketAddr>()` in `serve`.
`X-Forwarded-For`, `Forwarded`, cookies, usernames and request bodies are never
consulted for admission. An attacker therefore cannot mint a fresh limiter bucket
by spoofing a proxy header.

Both protected routes — the browser `POST /web/login` credential exchange and
the explicit `GET /api/auth/whoami` identity lookup — **fail closed** when the
transport peer is missing. Each returns the same fixed `503` body
(`authentication admission unavailable`) and performs no session, credential or
identity work. Neither route falls back to a forwarding header, a default
address or an invented identity. A served listener always installs
`ConnectInfo`; this path only matters for embedded or in-process routers that
omit it, and those requests are rejected rather than silently admitted.

## Configuration

All values are validated at startup. Invalid values fail `serve` before the
listener starts.

| Variable | Default | Meaning |
| --- | --- | --- |
| `ROOTYARD_AUTH_ADMISSION_MAX_INFLIGHT` | `4` | Concurrent admitted auth lookups, `1..=8`. Caps how many concurrent lookups this module can add to the shared pool; it does **not** reserve connections for anyone, because other, unbounded API routes can fill the 16-connection pool at the same time. |
| `ROOTYARD_AUTH_ADMISSION_ATTEMPTS_PER_SOURCE` | `10` | Attempts per peer address in a fixed window, `1..=1000`. |
| `ROOTYARD_AUTH_ADMISSION_SOURCE_WINDOW_SECONDS` | `60` | Fixed per-source window, `1..=3600`. |
| `ROOTYARD_AUTH_ADMISSION_MAX_SOURCES` | `4096` | Hard source-table entry bound, `1..=1000000`. |
| `ROOTYARD_AUTH_ADMISSION_SOURCE_TTL_SECONDS` | `300` | Idle source-table entry TTL, `1..=86400`; must be at least the window. |

The `429` response always carries `Retry-After: 60` and a fixed JSON body
(`authentication temporarily unavailable`) with `Cache-Control: no-store`. The
value is a constant, not a per-source remainder, so it cannot be used as an
identity or timing oracle. A capacity rejection and a rate rejection use the same
status/body, so an unauthenticated caller cannot distinguish them.

## Bounds and failure behaviour

- **Before the database:** admission checks the per-source fixed window and then
  tries to acquire an owned semaphore permit without queueing. Rate exhaustion or
  capacity overload returns `429` immediately; this request performs no pool
  checkout and no token-digest or username query.
- **Global budget:** at most `ROOTYARD_AUTH_ADMISSION_MAX_INFLIGHT` admissions are
  in flight in one process. The semaphore is deliberately small, which bounds
  this module's own contribution to pool pressure; it is not a reservation and
  does not shield the pool from unrelated routes. Permits are RAII: an explicit
  drop, an early return, a cancelled request future, an aborted task or a
  dropped connection releases capacity immediately.
- **Per-source budget:** a fixed window of
  `ROOTYARD_AUTH_ADMISSION_ATTEMPTS_PER_SOURCE` attempts keyed only by peer IP.
  Other sources keep independent budgets. There is no username key, so an
  attacker cannot lock a victim account out by generating failures.
- **Memory/TTL:** the source table never exceeds
  `ROOTYARD_AUTH_ADMISSION_MAX_SOURCES` entries in either index. Each live entry
  also has one `(last_seen, peer)` position in an ordered set, so refreshing a
  hot source is `O(log n)` and never accumulates stale positions. Expired
  entries are removed lazily with a fixed budget of at most 64 removals per
  admission check, and at the bound the least-recently-seen entry is evicted in
  `O(log n)`. No admission check scans the whole table, so per-request work does
  not grow with `max_sources`.
- **No secret/identity telemetry:** rejections carry fixed generic text. Counters
  are aggregate process counters with no labels and are not exported with peer,
  username or credential dimensions.

## Security trade-offs and remaining limits

- **Single-process budget:** the limiter and semaphore are process-local. With
  multiple replicas the effective budget multiplies by the replica count. A
  shared/distributed limiter is future issue-#84 work.
- **Loopback/NAT aggregation:** all clients behind one NAT/proxy share one peer
  address. A busy NAT can consume the per-source budget; conversely an attacker
  with many addresses gets many buckets. Deployments that need trusted proxy
  attribution must terminate at a proxy that preserves source identity and add an
  explicit trusted-hop design; arbitrary forwarding headers are intentionally not
  trusted here.
- **No account lockout:** this is intentional. Per-username lockout would let an
  attacker deny service to a victim and is not part of this slice.
- **Not a total request bound:** only the login/token-exchange and whoami paths
  are guarded. Every other existing API route remains unbounded by this module
  and keeps only its pre-existing database and Git concurrency controls; this
  module does not claim a global authentication or application capacity bound.
- **Not MFA/OIDC:** see explicit non-goals above.

## Verification

Deterministic Rust unit tests in `src/auth_admission.rs` cover fixed-window
limits, `429` + `Retry-After`, spoofed-header disregard, unrelated-source
isolation, semaphore RAII release (explicit drop, and a `tokio::spawn`ed task
that is aborted while holding the only permit), source-count/TTL bounds, the
bounded cleanup budget and index/map consistency under hot updates and source
rotation, missing-peer refusal, configuration validation and non-leaking
rejection bodies. They use injected `Instant` values and do not sleep.

The login route's fail-closed admission is unit-tested through the extracted
middleware gate helper (`is_login_attempt` + `admit_login_attempt`), which is
the exact code `login_middleware` runs before `Next::run`; the full middleware
path is exercised only by the native harness, because constructing `AppState`
requires a database pool and an axum `Next` cannot be built in a unit test. This
unit test asserts the `503` and `rejected_missing_peer` counter for a POST to
`/web/login` without `ConnectInfo`, admission with a real peer, and that other
routes/methods do not enter the gate.

`tests/auth_admission.py` is a native loopback harness. It runs the real binary
against a disposable PostgreSQL schema and real loopback TCP peers:

```sh
ROOTYARD_TEST_DATABASE_URL=postgres://... cargo test auth_admission # unit
ROOTYARD_TEST_DATABASE_URL=postgres://... python3 tests/auth_admission.py --binary target/debug/rootyard
```

It verifies response ordering and body equivalence (valid and invalid tokens
receive the same fixed `429` body), spoofed `X-Forwarded-For`/`Forwarded`
ignored, `127.0.0.2` isolated from a limited `127.0.0.1`, window recovery, the
login POST sharing the same gate, fixed `Retry-After`, and no bearer token in
rejection bodies or the server log. It does **not** inject database faults, so
it does not independently prove that a PostgreSQL query was skipped; it observes
the admission response and the pre-query code ordering, while the "no query on
rejection" property follows from that ordering and the admission unit tests.
