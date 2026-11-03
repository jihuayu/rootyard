# ADR 004: PostgreSQL deliveries with advisory wake transports

Status: implemented for standalone memory hints, polling workers, and Redis
Pub/Sub hints. Kafka is **not implemented or accepted** in this increment.
This is not GitFS multi-writer routing, automatic failover, or storage fencing.

## Authority and delivery contract

`outbox_events` and each consumer's `event_deliveries` in PostgreSQL remain the
only durable queue. A successful broker publish/subscription acknowledgment does
not claim, deliver, settle, or confirm any Git operation. The GitFS journal and
PG publication protocol from ADR 002 are unchanged. `unknown` remains unknown
until ADR 003's explicit audit-gap workflow; transports cannot resolve it.

After PG publication commits, the serving process sets two `Notify` permits:
one for its embedded worker and one for an optional background publisher. Each
holds at most one permit. Bursts coalesce, payloads contain no events, and a
publish error never changes the result of the preceding Git/PG operation. A
process dying before emitting the hint, offline reconciliation, a lost hint, or
Redis losing all state is repaired by scanning PostgreSQL. No transaction spans
PostgreSQL and Redis, and none is needed for this advisory contract.

Workers claim canonical PG rows with `FOR UPDATE SKIP LOCKED`, bounded batches,
and a durable owner/generation lease. Each local consumer applies its effect and
acknowledges in one PG transaction. The existing repository epoch, predecessor,
and lease checks run after locking; the transport never supplies a claim or an
event body. Multiple processes for the same consumer compete for the same
persistent delivery rows. The two fixed consumers, `audit-log` and `ref-index`,
have independent delivery state and per-ref order. A failed consumer does not
prevent the other consumer's scan. This is at-least-once processing with
idempotent transactional **local** effects, not external exactly-once delivery.

On termination or an uncertain PG acknowledgment, leases remain durable and can
be reclaimed after expiry. An old owner cannot acknowledge after another claim
advances the fence. Git storage locks are unnecessary for these PG-only effects;
they still take the shared repository row lock used by offline recovery.

## Process roles and configuration

`rootyard serve` keeps the embedded worker by default. Set
`ROOTYARD_OUTBOX_WORKER=false` to disable only that worker; provisioning and GitFS
journal recovery continue in the storage-owning process. Run one or more
`rootyard worker` processes for delivery. `rootyard worker-once` runs one bounded
scan and exits, printing the number of acknowledged effects.

Workers require `DATABASE_URL` and the existing PostgreSQL schema permissions.
They do not discover Git, open the data directory, acquire its flock, serve HTTP,
or reconcile GitFS journals. Startup applies the existing idempotent migrations;
there is no new schema migration in this increment. PostgreSQL must remain a
single correctly fenced authority. As with the main process, database TLS must
be provided by a local proxy; `sslmode=require` is rejected rather than silently
downgraded.

| Environment variable | Default | Bounds / meaning |
| --- | --- | --- |
| `ROOTYARD_WORKER_CONSUMERS` | `audit-log,ref-index` | Either fixed consumer alone or both, no duplicates |
| `ROOTYARD_WORKER_POLL_MS` | `5000` | 50–60000; periodic idle rescan interval |
| `ROOTYARD_WORKER_BATCH` | `64` | 1–1000 claims per consumer per scan |
| `ROOTYARD_WORKER_LEASE_SECONDS` | `60` | 1–3600; short leases may expire during work and cause retries |
| `ROOTYARD_WAKE_TRANSPORT` | `poll` | `poll` or `redis`; other values fail startup |
| `ROOTYARD_REDIS_ADDRESS` | none | Required for Redis, numeric loopback socket address with nonzero port |
| `ROOTYARD_WAKE_CHANNEL` | `rootyard:outbox:v1` | 1–128 ASCII alphanumeric, colon, underscore or hyphen |

Example role split (set the database URL using your normal secret mechanism):

```sh
ROOTYARD_OUTBOX_WORKER=false rootyard serve
ROOTYARD_WORKER_CONSUMERS=audit-log rootyard worker
ROOTYARD_WORKER_CONSUMERS=ref-index rootyard worker
```

Each worker scans immediately on startup. A fixed ticker is independent of
broker activity and is not reset by hints or reconnect attempts. Successful
batches schedule another scan to drain a backlog. A 25 ms minimum delay bounds
continuous wake floods. Consumers run independently with 15-second scan timeouts
and a 30-second outer watchdog. The configured poll period is a scheduling bound
while idle, **not** a delivery-latency guarantee: database contention, query
timeouts, backoff, lease expiry, and queue backlog can delay completion. Failed
or cancelled batches leave durable rows for retries. SIGTERM/SIGINT cancel
subscription and network waits; cancelled in-flight PG transactions do not create
an unfenced external effect.

## Redis adapter and extension interface

The `WakeTransport` interface exposes only publish-a-hint and subscribe-to-hints.
It accepts no repository, user, token, ref, object ID, operation ID, or event
payload. Redis uses a separate publisher connection and dedicated RESP2 subscriber
connection, channel-specific `SUBSCRIBE`, and the exact payload `v1`. Subscription
acknowledgments and frames are validated. Connect/publish/subscribe handshakes
have one-second timeouts, reads have a 60-second deadline, and reconnect waits one
second. A successful subscription causes a PG catch-up scan. Parsing bounds
aggregate frame bytes (1024), line bytes (256), bulk bytes (256), array members
(3), and nesting before allocation. Invalid frames disconnect; they never execute
an effect. Errors log fixed descriptions, not Redis payloads or credentials.

Only plaintext loopback connections are supported. For a remote Redis server,
provide an already configured local authenticated TLS proxy/tunnel; Rootyard does
not create credentials, configure that proxy, or support Redis AUTH, TLS, Sentinel,
Cluster discovery, or arbitrary remote addresses here. Keep the local port
private. Use distinct non-sensitive channel names for separate installations:
Redis database numbers do not isolate Pub/Sub channels. A wrong/shared channel
can change wake latency or cause unnecessary scans, not delivery correctness.

Redis Pub/Sub is at-most-once and drops messages while subscribers disconnect.
That behavior is intentional for hints; PG polling is mandatory, including when
Redis is configured. See the [Redis Pub/Sub contract](https://redis.io/docs/latest/develop/pubsub/)
and [RESP specification](https://redis.io/docs/latest/develop/reference/protocol-spec/).

A future Kafka adapter could implement the same **advisory** interface; it must
not reinterpret offsets as PG effect acknowledgments, rely on broker ordering
instead of PG per-ref barriers, or move durable authority into an in-memory queue.
Kafka client integration, broker restart/rebalance, authentication, and deployment
are unimplemented and untested. Generic fake-adapter tests do not certify Kafka.
External side-effect consumers would require their own durable idempotency and
acknowledgment protocol and are outside this interface.

## Verification scope

Unit tests cover parser/endpoint limits, coalescing 100,000 hints to one permit,
and cancellation of a failed advisory publisher. `tests/cross_process.py` uses
isolated PostgreSQL, actual independent worker processes, and an optional local
Redis executable. It emits a JSON report containing the tested binary SHA-256 and
explicitly reports missing real-Redis coverage. CI installs Redis and requires the
real-service cases. Run only against a dedicated test database:

```sh
ROOTYARD_TEST_REDIS_SERVER=/path/to/redis-server \
  python3 tests/cross_process.py --binary target/debug/rootyard \
  --report test-results/cross-process.json
```

These tests are single-host process/network fault tests. They do not test Redis
HA, Redis TLS proxies, Kafka, PG failover, kernel/power loss, multi-host fencing,
or production performance. The backup/restore and repository-routing workstreams
remain separate.

### Recorded local results (2026-11-03)

Debug binary SHA-256:
`9292dfe5b02075a22c8e3080dc74f7182d478d06a3883a186ae41c1b8075d89f`.

- All six cross-process cases passed with real PostgreSQL 17.11 and isolated
  Redis 7.2.7, twice consecutively. Each run finished with 71 events and 142
  durable consumer acknowledgments. Four workers were active; multiple distinct
  lease owners actually claimed work. Delivery traces verified per-consumer,
  same-ref sequence and a projection matching the latest receipt.
- The suite also verifies publication before subscribers, independent consumer
  selection, no Git/data-directory dependency, audit-effect failure isolation,
  real worker SIGKILL during a test-trigger-paused transaction, expired lease
  recovery, and Redis SIGKILL/restart with publication while disconnected.
- Duplicate, wrong-version, oversized, wrong-channel and forged event-looking
  hints do not create events/effects. A 60-second polling interval with delivery
  inside a five-second observation window verifies actual Redis wake publication.
- The same binary passed 27 Rust unit tests, both explicitly enabled PostgreSQL
  integration tests (`outbox`, `resolution_fences`), and all 15 baseline + 18
  reliability + 7 manual-recovery cases separately with Git 2.47.3 and 2.56.0.
  Five metrics cases passed. Formatting, Clippy with denied warnings, and the
  release build passed.

The reports distinguish actual process failures from the test-only SQL pause and
reject triggers. No Kafka, Redis HA, remote proxy, or PG failover result is implied.

The initial CI run exposed a test-fixture portability error: Debian's Redis 8
`redis-server` entry point resolves to a multicall executable whose basename
selects `redis-check-rdb` mode. The harness now preserves the configured
executable's entry-point name rather than resolving its symlink. The same layout
is reproduced locally; this changes only test startup, not production transport
logic, and real Redis coverage is still required in CI.

## Paired restore and worker restart

The integrated offline backup captures durable PostgreSQL delivery rows together with GitFS and schema003 recovery evidence. Read [the backup contract](backup-restore.md): stop all target database clients, including PostgreSQL-only workers, until a restore succeeds and is reviewed. A crash guard on the target filesystem blocks serving, but these intentionally storage-independent workers do not consult it. Keep a failed or ambiguous target database isolated rather than starting workers merely because the database accepts connections.

After deliberate restart against the restored database, expired leases are reclaimed with increasing fencing generations; unexpired leases retain their original deadlines. Recovery snapshots and resolved unknown history remain protected, and old-generation ref candidates are retired rather than applied over a restored snapshot. Redis contains no recovery authority and requires no backup replay: polling recovers without any wake message. The integration drill in `tests/restored_workers.py` verifies these boundaries on two fresh local PostgreSQL clusters before real authenticated clone/push and standalone delivery. See [integrated worker verification](workers-integration-verification.md).
