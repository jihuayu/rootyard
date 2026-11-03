# Kafka advisory wake adapter

This increment implements Kafka transport behind the same `WakeTransport`
interface as Redis. PostgreSQL is still the only durable queue. Kafka records,
producer acknowledgments, committed offsets, partition ownership and consumer
rebalances never acknowledge a PG effect, settle an unknown Git operation, or
change GitFS ownership. See [the delivery contract](cross-process-workers.md).

## Supported isolated slice

The client is pinned by Cargo.lock to rust-rdkafka 0.39.0 and bundled librdkafka
2.12.1, statically built from the crates.io package. This adds a native C build
requiring a compiler, make and pkg-config. The build disables optional TLS/SASL,
zlib and zstd features; the bundled native library still has built-in codec
capabilities. Do not infer that disabling outgoing compression prevents incoming
compressed-batch processing.

Configure an already running, operator-controlled **local** Kafka broker with a
dedicated non-sensitive wake topic and group. No topics, accounts, credentials,
ACLs, external services or deployments are created by Rootyard.

```sh
export ROOTYARD_WAKE_TRANSPORT=kafka
export ROOTYARD_KAFKA_BOOTSTRAP_SERVERS=127.0.0.1:9092
export ROOTYARD_KAFKA_TOPIC=rootyard.wakes.v1
export ROOTYARD_KAFKA_GROUP=rootyard.workers.v1
# Set DATABASE_URL using your usual secret mechanism.
ROOTYARD_OUTBOX_WORKER=false rootyard serve
rootyard worker
```

The bootstrap list allows 1–4 numeric loopback socket addresses with nonzero
ports. Topic and group names allow 1–128 ASCII letters, digits, `.`, `_` and `-`,
excluding `.` and `..`; topic names beginning with `__` are rejected to protect
Kafka internal topics. Names must not contain personal data or secrets. Only
PLAINTEXT is implemented. This is not a remote Kafka authentication/TLS setup.

**Bootstrap validation is not network confinement.** Kafka supplies advertised
broker/controller endpoints in metadata. All advertised endpoints must also be
trusted local endpoints, and operators must enforce network restrictions outside
the client. Do not point this adapter at an untrusted broker or expose its topic
to untrusted producers. SASL, TLS, remote proxy routing, ACL provisioning and
multi-broker security are outside this slice.

Use a dedicated topic with a small fixed partition count (the tested profile is
two, deployment contract at most 16), `compression.type=uncompressed`,
`max.message.bytes=4096`, bounded retention, and no automatic topic creation.
Rootyard disables client auto-creation but does not administer or continuously
verify topic settings. For an isolated single-broker test only:

```sh
kafka-topics.sh --bootstrap-server 127.0.0.1:9092 --create \
  --topic rootyard.wakes.v1 --partitions 2 --replication-factor 1 \
  --config compression.type=uncompressed --config max.message.bytes=4096 \
  --config retention.ms=3600000
```

Replication factor one, plaintext and the combined KRaft broker/controller used
in tests are explicitly not a production or HA recommendation.

## Hint, offset and group semantics

The only emitted record has payload `v1`, no key and no headers. Received records
must match all three conditions before notifying a worker. Wrong versions,
forged event-looking JSON, keyed/header-bearing messages and oversized application
payloads are ignored. Broker input never selects a PG consumer, repository, ref,
claim, or effect. Client logs suppress arbitrary broker text and use fixed
unavailability warnings.

A capacity-one in-process mailbox feeds a native producer with a one-message,
1 KiB queue, one-message batches, no compression and a one-second message timeout.
Enqueue never waits for queue capacity. The existing publisher also has its
one-second async deadline. Cancellation can leave an already-enqueued hint in
Kafka, so late/duplicate delivery is normal and harmless. No broker outcome can
turn a previously committed Git/PG operation into failure.

The consumer uses the classic group protocol and cooperative-sticky assignment.
Default native rebalance assignment remains intact; an assignment callback emits
a PG catch-up hint. Group members may share the wake partitions, but durable
work ownership is still decided by PG row claims and lease generations. Different
Kafka groups can all see the same hints without duplicating PG effects. Kafka
groups and `ROOTYARD_WORKER_CONSUMERS` are separate concepts; role-specific groups
can improve wake latency, but correctness never depends on them.

Offsets are auto-stored and periodically auto-committed for hints only. They may
advance before any PG effect, and a new group starts at the current end. Neither
can lose durable work because workers scan PG immediately and on their fixed
mandatory interval. Broker loss, retained-record expiry, offset resets, missed
hints, duplicate delivery, reordered hints and rebalance pauses do not remove
PG delivery rows. Per-ref order, effect idempotency, unknown barriers and recovery
fences continue to be checked inside the PG transaction.

## Resource and lifecycle boundaries

Consumer settings limit the prefetched queue to 64 KiB (native soft limit), fetch
requests to 32 KiB and explicit protocol receive responses to 64 KiB. Initial
per-partition fetch size and `message.max.bytes` are 4096. These settings have
native-library exceptions: fetch limits may grow for an oversized first batch,
queues may overshoot, metadata/partition state consumes additional memory, and
compressed batches can allocate decompressed data before application validation.
**They are not a hard total-RSS or hostile-broker memory guarantee.** The trusted,
uncompressed, bounded dedicated topic and deployment memory/process limits are
required. Use PG polling if that boundary cannot be satisfied. A poisoned record
can prevent hints from a partition while PG polling continues to make progress.

Each adapter owns at most one producer thread and each worker subscription one
consumer thread. Native client creation, polling and destruction run on dedicated
OS threads; the application Tokio worker handles only bounded channels and
cancellation. Stopping or dropping a subscription cancels its polling thread.
Native cleanup can continue on that thread after the async task stops; a Kafka
session timeout is not a proven wall-clock destructor deadline. There is no
unbounded retry loop spawning replacement cleanup threads. Process shutdown
terminates remaining threads; no Kafka cleanup holds a PostgreSQL transaction.

Transient broker loss is retried by librdkafka while PG polling proceeds. If
native runtime/thread/client initialization itself fails, the adapter stays
degraded until process restart (publisher creation can retry only if its thread
was not created). This is safe for durability but is an operational limitation,
not automatic adapter self-repair. Worker/API process health alone does not prove
broker health; use durable backlog metrics and fixed degraded logs.

The [librdkafka configuration contract](https://github.com/confluentinc/librdkafka/blob/v2.12.1/CONFIGURATION.md)
describes queue/fetch limits and offset behavior. The
[rust-rdkafka producer API](https://docs.rs/rdkafka/0.39.0/rdkafka/producer/struct.FutureProducer.html)
distinguishes enqueue and delivery timeouts, and its
[consumer context API](https://docs.rs/rdkafka/0.39.0/rdkafka/consumer/trait.ConsumerContext.html)
describes rebalance callbacks.

## Reproducible tests and acceptance boundary

`tests/kafka_wakes.py` starts an owned loopback KRaft broker from
`ROOTYARD_TEST_KAFKA_HOME`, temporary storage and actual application workers. An
explicit invalid Kafka path fails rather than silently skipping. Without a
configured installation, the report must clearly mark real Kafka coverage as
skipped. CI downloads the official Kafka 4.4.0 archive, checks its pinned SHA512,
uses Java 21, and requires the real broker cases.

```sh
ROOTYARD_TEST_DATABASE_URL=postgresql://localhost/rootyard_test \
ROOTYARD_TEST_KAFKA_HOME=/path/to/kafka_2.13-4.4.0 \
  python3 tests/kafka_wakes.py --binary target/debug/rootyard \
  --report test-results/kafka.json
```

The database must be dedicated to tests. Unit tests additionally exercise strict
endpoint/name/payload admission and cancellation/drop on a single-thread Tokio
runtime with an unavailable broker. That test proves application-runtime isolation,
not an upper bound on native cleanup time. Cross-process Redis and all prior Git,
PG outbox, explicit-recovery and metrics suites remain part of CI.

No result here proves Kafka replication durability, multi-broker/controller
failover, remote TLS/SASL operation, PG failover, storage-node takeover, kernel or
power-loss behavior, or production throughput/RPO/RTO. Kafka is still replaceable
by polling without changing the application correctness contract.

### Recorded local verification (2026-11-03)

Final debug executable SHA-256:
`ac42299128663cefd46504c27d82c43ef17386f9ed2be85527fccf44fc30ce48`.
The test verifies that the executable hash remains unchanged from start to finish.

Actual Kafka 4.4.0, OpenJDK 21.0.12.1, PostgreSQL 17.11 and Git 2.52.0 passed the
Kafka fixture and application scenario (two named cases containing many checks):

- Actual Rootyard consumer membership became stable at 1, then 2, then 1 member;
  the official Kafka CLI only observed the application group.
- Broker SIGKILL and restart retained the fixture and allowed clients to rejoin.
  Git pushes and PG delivery continued while Kafka was absent.
- Wrong/2048-byte payloads and keyed `v1` did not even wake a long-poll worker;
  its pending PG rows remained. Kafka rejected an 8192-byte record under the
  topic's 4096-byte limit. A later valid hint drained the pending rows.
- The run ended with 25 events and 50 PG transactional effects, with per-ref
  delivery order and latest-receipt projections checked.
- With PG polling set to 60 seconds, a real publisher wake completed in 0.096
  seconds and a later wake in 0.571 seconds. Worker and application process exit
  while the broker was down took under 0.01 seconds in this run. These are local
  observations, not guaranteed latency or native-destructor deadlines.

The same final binary passed 29 Rust unit tests, both explicit PG integration
suites, all 15 baseline + 18 reliable-event + 7 recovery cases independently with
Git 2.47.3 and 2.56.0, five metrics cases, and all six real Redis cross-process
cases. Formatting, warning-free Clippy, release compilation, and a separate empty
Cargo target-directory build of the native dependency passed. CI repeats these
checks with a fresh container and a checksum-verified real Kafka distribution;
local tests do not substitute for its result. A separate CI job builds the
Dockerfile including its explicit native build prerequisites; no image is pushed
or deployed. Docker was unavailable in the local workspace.
