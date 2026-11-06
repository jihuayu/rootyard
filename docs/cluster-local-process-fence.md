# Local-host cluster and process fence

This profile runs separate Rootyard processes and storage volumes on one Linux
host, backed by one PostgreSQL 17 database. It supports measured replica
transfer and automatic takeover only when a trusted local process-session fence
is configured. It is a functional reference profile, not cross-host HA.

Each process needs a distinct `ROOTYARD_NODE_ID`, `ROOTYARD_BIND`, and
`ROOTYARD_DATA_DIR`. All processes share the same `DATABASE_URL`, a base64
`ROOTYARD_CLUSTER_HMAC_KEY` containing at least 32 random bytes, and an
absolute `ROOTYARD_LOCAL_FENCE_DIR`. Create the fence directory as the service
UID with mode `0700`, outside every node volume. Launch each `rootyard serve`
as its own Linux session leader, for example with `setsid`; startup rejects a
process that is not isolated this way. The fence directory must survive
process restarts. A single host UID controls all nodes in this profile, so it
must be treated as an operator identity.

The operator registers each process through `POST /api/shards/nodes` using a
cluster-operator token. Use `role=primary` for the initial owner and
`role=replica` for a standby; provide the actual loopback endpoint and a
nonzero `lease_ttl_seconds` such as `5`. The processes renew their leases while
healthy. The HMAC key authenticates short-lived, one-use, repository/actor/
epoch-bound internal requests. Git requests arriving at a different node are
streamed to the owner; the destination rechecks the actor's token, RBAC, and
route. A missing node identity in a multi-node cluster blocks Git ingress,
provisioning, and native writes.

From the current owner, call `POST /api/repos/{owner}/{name}/shard-migrate`
with `{"target_node_id":"node1","replicate_only":true}` and an optional
`operation_id` UUID to resume. The source holds the repository write lock,
creates a native Git bundle, and sends it to target staging. The target checks
the full object closure with `git fsck`, measures refs and journal sequence,
and records the verified operation. This does **not** cut over or serve stale
replica reads. A later acknowledged source write makes that measured copy
ineligible for takeover until it is refreshed.

When the old node lease expires, the standby first checks its local Git refs,
full fsck, journal sequence, and all acknowledged or unresolved PostgreSQL Git
operations. If data is stale, it remains read-only. If data is current, it
persists a restart block in the trusted fence directory, kills every process
group in the old node's isolated Linux session (including native Git backend
and hook descendants), and verifies the session is quiescent. Only then does
it compare and swap the route/generation under a PostgreSQL transaction lock,
record a failover operation, and publish the target volume marker. An
ambiguous marker publication leaves a durable pending transition and blocks
writes until reconciliation. A fenced old node cannot restart without an
operator resolving the persisted block. Retired source markers remain
read-only even if the old process is started with a wrong node identity.

For encrypted PostgreSQL connections, use a `DATABASE_URL` with
`sslmode=require` and set `ROOTYARD_PG_CA_PEM` to the trusted CA. The client
verifies the server hostname and supports optional
`ROOTYARD_PG_CLIENT_CERT_PEM`/`ROOTYARD_PG_CLIENT_KEY_PEM`. Supply the database
password in the connection URL through a secret manager. Backup/restore CLI
uses the same CA and `verify-full` policy. Kafka wake transport accepts
`ROOTYARD_KAFKA_SECURITY_PROTOCOL=SSL` or `SASL_SSL`, requires
`ROOTYARD_KAFKA_CA_PEM`, validates broker hostnames, and supports
`ROOTYARD_KAFKA_SASL_MECHANISM` with username/password credentials. Plaintext
Kafka is confined to numeric loopback endpoints. The cluster signing key and
all database/Kafka credentials must remain private to the service deployment.

The reproducible native checks are:

```sh
python3 tests/cluster_security_native.py --binary target/debug/rootyard
python3 tests/cluster_migration_native.py --binary target/debug/rootyard
python3 tests/cluster_takeover_native.py --binary target/debug/rootyard --report evidence/cluster-takeover-run.json
python3 tests/cluster_partition_native.py --binary target/debug/rootyard --report evidence/cluster-partition.json
python3 tests/cluster_workload_native.py --binary target/debug/rootyard --report evidence/cluster-workload-integration.json
python3 tests/cluster_tls_native.py --binary target/debug/rootyard --report evidence/cluster-tls.json
python3 tests/cluster_pg_streaming_native.py --binary target/debug/rootyard --report evidence/cluster-pg-streaming.json
python3 tests/cluster_kafka_tls_native.py --binary target/debug/rootyard --kafka-home /path/to/kafka_2.13-3.9.1 --report evidence/cluster-kafka-tls.json
```

These tests require the PostgreSQL 17 binaries, `ROOTYARD_TEST_DATABASE_URL`,
native Git, and a built Rust binary. The workload report measures 1/2/4
processes with distinct volumes, Git push/fetch, acknowledged-commit survival,
and process restart RTO. The takeover report also exercises a paused admitted
Git writer, stale replica rejection, a physically stopped source session,
duplicate node identities, and old-volume write denial. Neither report proves
cross-host storage fencing, PostgreSQL leader failover/PITR, kernel-level
network partition recovery, or a production RPO/RTO service-level objective. A multi-host
deployment must supply an external supported fencing and PostgreSQL HA system
and must not enable this local process driver across hosts.

The TCP isolation test cuts the source process's actual PostgreSQL socket path
while the target still reaches PostgreSQL. It verifies the isolated source
returns 503, the measured target takes over only after the source Linux
session is killed, and a new target Git push succeeds. This exercises a real
source-only TCP break through a disposable proxy; it is not a kernel network
namespace partition or a multi-host test.

The PostgreSQL streaming test starts a separate PostgreSQL 17 primary and
standby using verified TLS, SCRAM authentication, and synchronous
`remote_apply` commits. It writes and reads real Git data through Rootyard,
stops the primary during client reads, manually promotes the standby, restarts
Rootyard against the new endpoint, and checks acknowledged Git history before
and after a new push. This demonstrates a local functional failover path and
observed outage. It does not elect a database leader, prevent a manually
restarted old primary from becoming a second writer, archive WAL for PITR, or
automatically reconfigure applications. Production metadata HA therefore
requires an external supported solution with DCS, fencing, backup, and PITR.

The Kafka test uses the Apache Kafka 3.9.1 binary distribution and creates a
disposable KRaft broker with a TLS listener and SASL/PLAIN authentication.
Its client checks reject the wrong CA, hostname, and password. Rootyard then
publishes real wake messages after Git pushes, continues to acknowledge Git
operations while the broker is stopped (PostgreSQL remains authoritative),
and publishes another wake after the broker restarts. This verifies the local
encrypted dependency and reconnect path, but not a multi-broker Kafka cluster
or a remote Kafka failover. The test distribution can be obtained from
`https://archive.apache.org/dist/kafka/3.9.1/kafka_2.13-3.9.1.tgz`.
