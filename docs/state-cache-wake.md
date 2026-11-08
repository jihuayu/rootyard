# Bounded advisory state cache and wake boundary

Status: bounded increment implemented in `src/cache_wake/`. This work does **not**
claim that every consumer in issue 111 is cache-integrated (#110 consumer wiring
remains pending), and it does not move any authority into Redis. The cache
boundary is available and `MemoryCache::from_env` / `RedisCache::connect_from_env`
are explicit startup helpers; the serving process does not yet construct a cache
consumer.

## Authority boundary

Cache misses, evictions, TTL expiry, flushes, malformed values, Redis errors and
lost wake hints may only increase latency and cause an origin read. They must
never modify or decide:

- refs, manifest pointers or RefStore CAS results;
- durable tasks, deliveries or idempotency receipts;
- authentication or authorization;
- storage roots, holds, writer leases/fences or backup completion;
- hard quotas or billing reservations.

PostgreSQL and RefStore remain the durable authority. A last-value pointer in
Redis is only a hint; authoritative reads verify the version at the origin.
Warmup singleflight is ephemeral: it may expire, be cancelled or duplicate
computation, but any final artifact/ref publication must use the authoritative
CAS or fence. Redis is independently enableable and does not require Raft.

## Typed, versioned keys and values

Every key is built by `CacheKey::new` and contains:

```text
ry:cache:v1:{environment}:{schema}:{history_incarnation}:{tenant}:{repo}:{kind}:{version}:{digest}
```

`digest` is a truncated SHA-256 of an opaque discriminator, so raw tokens,
cookies, signed URLs and query text are not key material. Values carry a magic
header, kind code and version; decoding requires both to match the key. A stale
or mismatched value is a cache miss, never a cross-kind authorization signal.
`Debug` for `CacheKey`/`CacheValue` prints only kind, version and byte length,
never the encoded key, scope IDs or private value bytes.

Admitted `CacheKind` values are previews and display/route/negative-cache/wake/
advisory-rate hints only:

`git-object-preview`, `tree-listing`, `diff-view`, `ref-snapshot-hint`,
`issue-view`, `pull-view`, `route-directory`, `query-negative`, `wake-hint`,
`warmup-hint`, `advisory-rate`.

There is deliberately no auth, token, session, cookie, credential, secret or
hard-quota kind. Authorization still resolves from PostgreSQL on every
authoritative path. Redis soft limits are advisory only; hard quotas require a
durable PG/Ref-CAS reservation.

## Memory bounds and origin fallback

`CacheLimits` bounds Memory and origin fallback:

| Variable | Default | Meaning |
| --- | --- | --- |
| `ROOTYARD_CACHE_MAX_ENTRIES` | `4096` | Memory entry cap (Memory only) |
| `ROOTYARD_CACHE_MAX_BYTES` | `67108864` | Memory byte cap, key + encoded value (Memory only) |
| `ROOTYARD_CACHE_MAX_VALUE_BYTES` | `1048576` | Per-value cap for Memory and Redis |
| `ROOTYARD_CACHE_TTL_SECONDS` | `60` | Default TTL |
| `ROOTYARD_CACHE_MAX_TTL_SECONDS` | `3600` | Maximum accepted TTL |
| `ROOTYARD_CACHE_REQUEST_TIMEOUT_MS` | `1000` | Whole Redis operation deadline |
| `ROOTYARD_CACHE_MAX_INFLIGHT` | `32` | Redis in-flight request cap |
| `ROOTYARD_CACHE_ORIGIN_PERMITS` | `8` | Concurrent origin loads |
| `ROOTYARD_CACHE_ORIGIN_WAIT_MS` | `250` | Queue wait before `Busy` |
| `ROOTYARD_CACHE_ORIGIN_DEADLINE_MS` | `15000` | Absolute origin work deadline; exceeded gives `Deadline` |
| `ROOTYARD_CACHE_BREAKER_FAILURES` | `5` | Consecutive origin failures to open |
| `ROOTYARD_CACHE_BREAKER_COOLDOWN_MS` | `5000` | Breaker cooldown |

Memory uses a short in-process lock, entry/byte budgets and bounded insertion
order metadata. Replacing, deleting or expiring an entry removes its order
record, so metadata cannot grow past the entry cap. Redis uses an exclusive,
bounded idle pool of canonical multiplexed connections, an in-flight semaphore,
and one absolute deadline covering permit wait, connection checkout/creation
and every command. Failed or abandoned connections are discarded; subsequent
operations create replacements through the SDK. Reads issue `STRLEN` first and only a capped
`GETRANGE` (at most `max_value_bytes`) when it fits, so an oversized value is
never fully fetched. Writes reject oversized values before encoding/allocation.

No code path spawns an unbounded task or retries in a tight loop. Origin fallback
uses a semaphore, a bounded queue wait, a separate absolute origin-work
deadline and a consecutive-failure circuit breaker; overloaded, timed-out or
open-breaker callers receive
`Busy`/`Deadline`/`CircuitOpen` and must degrade explicitly. Dropping a timed-out
future is cooperative cancellation, not a guarantee that an underlying network
operation was stopped. Warmup singleflight has a bounded key map; a leader RAII
guard removes only its own generation on completion, error, panic or task abort,
and closes its watch channel so followers wake and retry/re-read. Producer output
remains non-authoritative and final publish must use PG/RefStore CAS.

## Optional Redis feature and resource contract

`Cargo.toml` declares:

```toml
state-redis = ["dep:redis"]
redis = { version = "=0.32.7", optional = true, default-features = false,
          features = ["tokio-rustls-comp", "connection-manager", "acl"] }
```

The pin is exact and must be validated by the build owner when regenerating
`Cargo.lock`. This increment was authored without network access, so the pin,
feature names and lockfile were not build-verified here. Do not hand-edit
`Cargo.lock`.

The `redis` crate (redis-rs) is a mature async client. This work adds no
hand-written RESP parser, raw TCP client or TLS implementation. Configure cache
with:

```sh
# Remote: TLS is mandatory. ACL username/password travel only in this secret URL.
ROOTYARD_CACHE_REDIS_URL='rediss://cache-user:secret@cache.internal:6380/0'
```

`rediss://` is required for a non-loopback endpoint. Plaintext `redis://` is
accepted only for `127.0.0.1`, `::1` or `localhost`. There is no redirect to a
plaintext fallback and cluster discovery is not enabled. URL parsing, ACL
credentials and TLS verification are delegated to redis-rs. Cache and wake
`Debug` output and error mappings print fixed descriptions, never URLs or
credentials.

`CacheLimits::max_entries` / `max_bytes` are **Memory-only**. They are not
silently passed to Redis: `RedisCacheLimits` deliberately omits them.
`RedisCache::connect` / `connect_from_env` requires a dedicated cache instance
whose `CONFIG GET maxmemory` is finite and at least `max_value_bytes`, and whose
`maxmemory-policy` is an `allkeys-*` or `volatile-*` eviction policy
(`noeviction` is rejected). Missing CONFIG permission, an unparseable response,
zero maxmemory or an unsupported policy fails startup closed. The contract is
cached after connect and revalidated (inside the same whole-operation deadline)
before every cache mutation (`SET`/`DEL`); if maxmemory or policy changes, the
mutation fails closed until an explicit reconnect revalidates it. Reads do not
revalidate on every call. This proves server-side evictability, not a per-key
aggregate logical count, a process-level hard quota, or a guarantee that the
operator will not change configuration between checks. Do not share the instance
with non-evictable or authoritative data.

The cache adapter is intentionally not wired into every read path yet. Consumers
must opt in and retain their PG/RefStore authority checks; this document does not
claim complete issue-111 consumer integration and explicitly leaves #110 consumer
wiring pending.

## Wake compatibility and configuration

`ROOTYARD_WAKE_TRANSPORT=poll` (default) and `memory` use local `Notify` permits.
Bursts coalesce, payloads contain no events, and PostgreSQL scanning remains
active.

With `state-redis` enabled, `ROOTYARD_WAKE_TRANSPORT=redis` uses the mature
adapter. It publishes only the fixed `v1` payload and notifies a PG rescan on a
valid subscribed message. A failed publish/subscription only affects wake
latency; the periodic PG scan remains authoritative.

| Variable | Default | Meaning |
| --- | --- | --- |
| `ROOTYARD_WAKE_TRANSPORT` | `poll` | `poll`, `memory`, `redis` or `kafka` |
| `ROOTYARD_REDIS_URL` | none | Feature path: `rediss://` remote or loopback `redis://`; ACL in URL |
| `ROOTYARD_REDIS_ADDRESS` | none | Legacy/compatibility loopback address, no credentials |
| `ROOTYARD_WAKE_CHANNEL` | `rootyard:outbox:v1` | 1–128 ASCII alphanumeric, colon, underscore or hyphen |

Existing explicit legacy settings are preserved when the feature is off: the
default build keeps the prior loopback-only `ROOTYARD_REDIS_ADDRESS` +
`ROOTYARD_WAKE_CHANNEL` adapter. That legacy path remains plaintext loopback and
is not a remote Redis deployment story. With the feature on, `ROOTYARD_REDIS_URL`
takes precedence, so `rediss://` and ACL credentials can be used without a TLS
proxy.

Redis Pub/Sub is at-most-once and drops messages while disconnected. Wrong
channel/payload and forged event-looking hints disconnect or are ignored; they
never execute an effect.

## Verification

Unit tests cover key versioning/typed values, redacted `Debug`, Memory
entry/byte/TTL bounds, bounded metadata under thousands of replacements/deletes
and expiry, origin semaphore queue-budget/body-not-polled plus absolute-work-
deadline/breaker bounds, singleflight coalescing, explicit leader abort with
follower wake and generation-safe cleanup, URL/TLS policy, channel bounds and
eviction-policy allowlist. Redis unit tests cover bounded-read length/corruption
as a miss, cheap pre-encode oversize rejection, whole-deadline permit wait and
refusal to operate without a validated server contract. Real-Redis contract tests
are `#[ignore]`d and require a dedicated server with maxmemory + eviction
configured and CONFIG permission:

```sh
ROOTYARD_TEST_REDIS_DESTRUCTIVE=owned-fixture \
ROOTYARD_TEST_REDIS_URL='rediss://user:secret@127.0.0.1:6380/0' \
SSL_CERT_FILE=/path/to/owned-fixture-ca.pem \
  cargo test --locked --features state-redis cache_wake::redis -- --ignored --test-threads=1
```

Missing `ROOTYARD_TEST_REDIS_URL` panics the explicitly selected contract test;
it is never reported as a successful real-Redis run. Do not point this at a
shared or production cache.

Root validation includes source-bound real Redis7.4.2 tests on a disposable
loopback instance:21 unit cases, six real cases over plaintext and again over
verified private-CA TLS, rejection with an untrusted CA and success after
restoring trust. Cases cover bounded reads, FLUSHALL, ACL rejection, unsafe
policy rejection/restoration, advisory wake and real driver teardown after
blackholed replies/caller abort. The selected report records exact source,
executable, fixture version and case counts in
`evidence/state-services/cache-wake/redis-contract.json`.

HA/Sentinel/Cluster, PG failover, production performance, least-privilege
production ACLs and complete serving-cache consumer wiring (#110) remain
unverified. This increment does not complete #111 or make Redis a hard quota or
authority. The default build still needs no Redis.

The full ignored real-Redis suite includes destructive FLUSHALL and CONFIG SET
checks. Run it only against a disposable, task-owned instance and explicitly set
`ROOTYARD_TEST_REDIS_DESTRUCTIVE=owned-fixture` as well as
`ROOTYARD_TEST_REDIS_URL`. This flag is an operator attestation, not automatic
proof of ownership. The cancellation test also requires an IPv4 loopback
endpoint; its byte-forwarding proxy changes only the port and uses the SDK for
all Redis/TLS handling. A TLS fixture certificate must cover 127.0.0.1.

Redis cache connections are now exclusively checked out from a bounded idle
pool. Only fully completed successful operations recycle their connection.
Error, deadline and caller cancellation paths drop the canonical redis-rs
connection, aborting its driver rather than retaining abandoned commands in a
shared manager. Wake publication uses one owned canonical connection per hint
behind a bounded permit. Physical teardown still requires runtime scheduling;
there is no claim to synchronously cancel kernel I/O. The stall regression
keeps the cache alive, blackholes real server replies and checks TCP closure
after repeated deadlines and an explicit caller abort, followed by recovery.
