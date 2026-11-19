# Bounded advisory state cache and wake boundary

Status: runtime `ServingCache` (`src/cache_wake.rs`, `src/cache_wake/{types,breaker,serving,memory,origin,redis}.rs`)
and `src/browse/` serving consumers (`src/browse/{cache,cache_models,handlers}.rs`) are
wired for Issue #111. The standalone `blob_git_gateway` / `serve-blob` A4 path now has
an explicit opt-in advisory publisher and an A4-only external worker scope; the default
remains Memory cache + local `Notify` + PostgreSQL target-audit scanning. Redis remains
optional and strictly non-authoritative: a default build compiles no Redis dependency,
and no cache or wake value can become delivery authority.

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
ry:cache:v2:{environment}:{authority}:{schema}:{history_incarnation}:{tenant}:{repo}:{kind}:{version}:{digest}
```

Both `environment` (from `ROOTYARD_CACHE_ENVIRONMENT`) and `authority`
(`gitfs`, `pando`, `git-native`) are validated lowercase ASCII scope tokens.
`environment` defaults to `"serving"` only when the variable is absent. A
present empty, malformed, overlong, uppercase, or non-Unicode value fails
closed before any cache read or write; it is never substituted with the
default, and the raw value is not echoed in the fixed service-unavailable
error. In `src/browse/cache.rs`, `history_incarnation` hashes the
volume ID, repository ID, authority, `object_format`, and `backend_transition_epoch`,
while `version` carries PostgreSQL `storage_generation`. Any backend switch,
format transition, or generation bump moves keys to a disjoint namespace without
depending on Redis `DEL` or key scans.

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
| `ROOTYARD_CACHE_BACKEND` | `memory` | `memory` (default, no Redis dependency) or `redis` (`state-redis` required) |
| `ROOTYARD_CACHE_ENVIRONMENT` | `serving` only when absent | Optional validated scope token; a present invalid or non-Unicode value fails closed before cache access |
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

## Serving runtime (`ServingCache`) and `src/browse/` integration

`ServingCache` (`src/cache_wake/serving.rs`) wraps `MemoryCache` (default) or
optional `RedisCache` (`ROOTYARD_CACHE_BACKEND=redis` with `state-redis`):

1. **Startup contract**: invalid backend names, `ROOTYARD_CACHE_BACKEND=redis`
   without `state-redis`, invalid/plaintext remote URLs, or missing/unsafe
   Redis `CONFIG` (`maxmemory` / `noeviction`) fail startup closed. Standalone
   callers use `ServingCache::standalone_memory()` with zero Redis dependency.
2. **Runtime degrade & recovery**: runtime Redis errors, timeouts, `FLUSHALL`,
   corrupt JSON payloads (`#[serde(deny_unknown_fields)]`), or an open advisory
   half-open breaker (`src/cache_wake/breaker.rs`) degrade cleanly to origin
   loads (`OriginGuard` + `SingleFlight`, never letting client `404`/`400`
   responses trip the origin breaker) and recover automatically once Redis
   returns after cooldown.
3. **Authz-first & origin-verified browse reads**: `src/browse/handlers.rs` and
   `src/browse/cache.rs` authorize every request against PostgreSQL (`authorize_repo_with_role`
   + active token/scope checks) *before* touching `ServingCache`. `list_refs`
   verifies `RefSnapshotHint` against origin; mutable branch/`HEAD` lookups for
   `get_tree` / `get_blob` resolve their authoritative tip OID at origin before
   keying immutable `TreeListing` / `GitObjectPreview` entries.

## Explicit A4 target-audit wake (`serve-blob` / external worker)

The standalone `blob_git_gateway` producer and its target-audit subscriber can be
split across processes without changing PostgreSQL authority. This is an explicit,
default-off topology; `serve-blob` without the A4 variables keeps the in-process
Memory cache, local `Notify` hints and periodic target-audit scan. The generic
`ROOTYARD_WAKE_TRANSPORT`, `ROOTYARD_WAKE_CHANNEL` and
`ROOTYARD_WORKER_CONSUMERS` variables are **not** read by this A4 path, so an
A4 worker cannot be broadened to the legacy `ref-index` consumer or Ref-CAS
projection jobs by them. The generic scope itself is unchanged and keeps its
existing full `audit-log` scan.

| Variable | Default | Meaning |
| --- | --- | --- |
| `ROOTYARD_A4_WORKER_MODE` | `embedded` | `embedded` keeps the in-process target-audit consumer; `external` removes it for a separately supervised A4 worker |
| `ROOTYARD_A4_WAKE_TRANSPORT` | absent (`poll`) | `poll`/`memory` (no remote), or `redis` (requires `state-redis`) |
| `ROOTYARD_A4_WAKE_CHANNEL` | `rootyard:a4:pg_refstore_core_commit_audit:v1` | Validated 1–128 ASCII alphanumeric/colon/underscore/hyphen A4 namespace; never a secret or payload |
| `ROOTYARD_WORKER_SCOPE` | `generic` | On `rootyard worker`/`worker-once`: `generic` or the explicit `a4-target-audit` scope |

Producer (`serve-blob`):

- `ROOTYARD_A4_WORKER_MODE=external` is the explicit external-placement mode. It
  launches no in-process A4 consumer at all, so the separately supervised
  `ROOTYARD_WORKER_SCOPE=a4-target-audit` process is the only claimant. The
  default `embedded` mode and every value other than the exact `external` token
  keep the embedded consumer; unknown modes fail startup. External placement is
  valid with no A4 transport (the external worker then uses its mandatory PG
  ticker), with `poll`/`memory`, or with the feature-gated `redis` publisher.
- `ROOTYARD_A4_WAKE_TRANSPORT=redis` selects the existing feature-gated
  `RedisWake` using `ROOTYARD_REDIS_URL` or the loopback
  `ROOTYARD_REDIS_ADDRESS`. Without `state-redis`, selecting `redis` fails
  startup closed; no Redis crate is compiled into the default build. Startup
  validates the URL/channel policy but does not require Redis reachability, and
  an external placement never waits for Redis before serving.
- The gateway still calls `Signals::committed()` only after a fresh authorized A4
  durable transaction, including its audit outbox projection, has committed. The
  call stores a local and a remote `Notify` permit and does not await Redis. In
  external placement the local permit has no consumer; the remote permit feeds
  the optional publisher when configured. The separate publisher task has its own
  one-second publish deadline and swallows publish errors into a fixed diagnostic;
  a slow, disconnected or lost publish cannot delay or alter the acknowledged
  commit, terminal, refs, holds, roots or outbox rows.
- The publisher shares the existing dispatch stop token, is cancelled on every
  listener/worker/signal/barrier exit path and is bounded-awaited during drain,
  whether or not an embedded worker exists.

Subscriber (`rootyard worker` in A4 scope):

- `ROOTYARD_WORKER_SCOPE=a4-target-audit` selects a target-audit-only
  `Settings`: consumer `audit-log`, `events::TARGET_AUDIT_KIND`,
  `projection_jobs=false`. `worker-once` uses the same scoped claim helper.
  It never executes the generic `ref-index` effect or `ref_cas_projection_jobs`.
- The fixed ticker remains active independently of Redis. A subscription
  acknowledgment triggers a catch-up scan; reconnect also triggers one. Wrong
  channel/payload frames disconnect. Duplicate or lost hints may only cause an
  extra or delayed PostgreSQL scan; they cannot claim, acknowledge, settle or
  choose a row. Missing/expired state still fails the normal PG lease and
  authority checks.
- Redis carries only the existing fixed `v1` hint on the A4 Pub/Sub channel. It
  contains no repository, operation, ref, token, user, permission, hold, root or
  event payload, and holds no durable work.

Example role split (endpoint/credentials supplied by the normal secret
mechanism; use a distinct channel per installation):

```sh
# Producer with no in-process A4 consumer; publisher remains advisory.
ROOTYARD_A4_WORKER_MODE=external \
ROOTYARD_A4_WAKE_TRANSPORT=redis \
ROOTYARD_REDIS_URL='rediss://cache-user:secret@cache.internal:6380/0' \
  rootyard serve-blob

# The only A4 consumer. It still scans PG on its fixed ticker if Redis is down.
ROOTYARD_WORKER_SCOPE=a4-target-audit \
ROOTYARD_A4_WAKE_TRANSPORT=redis \
ROOTYARD_REDIS_URL='rediss://cache-user:secret@cache.internal:6380/0' \
  rootyard worker
```

Omitting `ROOTYARD_A4_WORKER_MODE` keeps the embedded consumer. An external
placement with no `ROOTYARD_A4_WAKE_TRANSPORT` is also valid: `serve-blob` simply
has no publisher and the external worker relies on PG polling.

Keep the existing `ROOTYARD_OUTBOX_WORKER=false` + generic `rootyard worker`
roles separate. The A4 scope is a separate queue/namespace, not a replacement for
the generic outbox consumers. The real PG17/Garage/Redis A4 acceptance (actual
serve-blob HTTP/stock Git, exact-once target audit, partition fallback and
post-heal wake before poll) is a separate gate and is not claimed by the source
tests in this worktree.

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
eviction-policy allowlist. `src/dispatch.rs` unit tests cover the explicit A4
worker scope, the A4-scoped valid channel, the default-off transport selection
the explicit external/embedded placement and the no-feature Redis refusal.
Source-only Python guards in `tests/test_a4_redis_wake.py` and
`tests/test_blob_gateway_memory_wake.py` cover the producer/subscriber wiring,
publisher stop ownership, conditional external consumer removal, post-commit
trigger ordering and the absence of legacy consumer/projection enrollment. The
opt-in external acceptance entry point and its pure timing/report/cleanup guards
live in `tests/a4_redis_wake_partition.py` and
`tests/test_a4_redis_wake_partition.py`; they do not replace the required native
PASSED report. Redis unit
tests cover bounded-read length/corruption as a miss, cheap pre-encode oversize
rejection, whole-deadline permit wait and refusal to operate without a validated
server contract. Real-Redis contract tests are `#[ignore]`d and require a
dedicated server with maxmemory + eviction configured and CONFIG permission:

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

HA/Sentinel/Cluster, PG failover, production performance and least-privilege
production ACLs remain pending. The `serve-blob`/A4 advisory producer and
subscriber wiring is implemented behind the explicit variables above, but the
real PG17/Garage/Redis external A4 acceptance remains pending: the opt-in entry
point is `tests/a4_redis_wake_partition.py` with pure tests in
`tests/test_a4_redis_wake_partition.py`, but no native PASSED report is claimed
in this worktree. This increment keeps #111 open for that run and never makes
Redis a hard quota or authority. The default build still needs no Redis.

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

## Optional CI real-Redis gate

`scripts/check_redis_contract.py` owns a disposable Docker `redis:7.2.6`
fixture and runs the source-bound six-case plaintext, TLS, untrusted-CA and
restored-trust contract. The separate `.github/workflows/redis-contract.yml`
job wraps it with all-target `state-redis` Clippy and report upload. Remote CI
execution is pending in this worktree; no remote PASSED result is claimed.
See [owned real-Redis contract gate](redis-contract-gate.md).
