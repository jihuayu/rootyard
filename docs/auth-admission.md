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

`GET /api/auth/whoami` is the new auth-protected route for this slice. It refuses
a missing peer with a fixed `503` instead of inventing an identity or trusting a
header. The existing login route is also admitted when a peer exists; in-process
router construction without `ConnectInfo` keeps the historical compatibility path
so unrelated internal router tests are not required to fabricate a socket. A
served listener always supplies `ConnectInfo`.

## Configuration

All values are validated at startup. Invalid values fail `serve` before the
listener starts.

| Variable | Default | Meaning |
| --- | --- | --- |
| `ROOTYARD_AUTH_ADMISSION_MAX_INFLIGHT` | `4` | Concurrent admitted auth lookups, `1..=8`. Must stay well below the PostgreSQL pool size of 16 so ordinary repository traffic keeps database capacity. |
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
  capacity overload returns `429` immediately; no connection is checked out and
  no token digest or username query runs.
- **Global budget:** at most `ROOTYARD_AUTH_ADMISSION_MAX_INFLIGHT` admissions are
  in flight in one process. The semaphore is deliberately small relative to the
  16-connection pool. Permits are RAII: an explicit drop, an early return, a
  cancelled request future or a dropped connection releases capacity immediately.
- **Per-source budget:** a fixed window of
  `ROOTYARD_AUTH_ADMISSION_ATTEMPTS_PER_SOURCE` attempts keyed only by peer IP.
  Other sources keep independent budgets. There is no username key, so an
  attacker cannot lock a victim account out by generating failures.
- **Memory/TTL:** the source table never exceeds
  `ROOTYARD_AUTH_ADMISSION_MAX_SOURCES` entries. Expired entries are pruned and,
  at the bound, the least-recently-seen entry is evicted. This bounds process
  memory but also means a distributed source rotation can displace old buckets;
  the global in-flight semaphore remains the hard database-protection bound.
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
  are guarded. Other authenticated APIs keep their existing database and Git
  concurrency controls; this module does not claim a global authentication or
  application capacity bound.
- **Not MFA/OIDC:** see explicit non-goals above.

## Verification

Deterministic Rust unit tests in `src/auth_admission.rs` cover fixed-window
limits, `429` + `Retry-After`, spoofed-header disregard, unrelated-source
isolation, semaphore RAII/cancellation release, source-count/TTL bounds, missing
peer refusal, configuration validation and non-leaking rejection bodies. They
use injected `Instant` values and do not sleep.

`tests/auth_admission.py` is a native loopback harness. It runs the real binary
against a disposable PostgreSQL schema and real loopback TCP peers:

```sh
ROOTYARD_TEST_DATABASE_URL=postgres://... cargo test auth_admission # unit
ROOTYARD_TEST_DATABASE_URL=postgres://... python3 tests/auth_admission.py --binary target/debug/rootyard
```

It checks `429` rejection before credential verification (valid and invalid
tokens get the same body), spoofed `X-Forwarded-For`/`Forwarded` ignored,
`127.0.0.2` isolated from a limited `127.0.0.1`, window recovery, the login POST
sharing the same gate, fixed `Retry-After`, and no bearer token in rejection
bodies or the server log.
