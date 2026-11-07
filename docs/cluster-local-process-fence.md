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
streamed to the owner. Git-backed browse GETs and atomic ref-transaction POSTs
use the same owner route; the destination rechecks the actor's token, RBAC,
route epoch, and storage generation before its handler accesses GitFS. Browse
handlers also recheck authorization after waiting for the PostgreSQL data
lease. A missing node identity in a multi-node cluster blocks Git and browse
ingress, provisioning, and native writes.

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
python3 tests/cluster_pg_pitr_native.py --binary target/debug/rootyard --report evidence/cluster-pg-pitr.json
python3 tests/cluster_disk_pressure_native.py --binary target/debug/rootyard --report evidence/cluster-disk-pressure.json
python3 tests/cluster_kafka_tls_native.py --binary target/debug/rootyard --kafka-home /path/to/kafka_2.13-3.9.1 --report evidence/cluster-kafka-tls.json
python3 tests/cluster_operations_gate.py --evidence-dir evidence --report evidence/cluster-operations-gate.json
```

The gate script validates that every native report carries matching source,
binary, harness, tool, topology, dataset, workload, hardware and limits
provenance and that no simulated field satisfies a gate. The full operations
map, restore ordering, RPO/RTO assumptions, upgrade/rollback and untested
boundaries are in [cluster-operations.md](cluster-operations.md).

These tests require the PostgreSQL 17 binaries, `ROOTYARD_TEST_DATABASE_URL`,
native Git, and a built Rust binary. The workload report measures 1/2/4
processes with distinct volumes, Git push/fetch, acknowledged-commit survival,
cross-node browse/ref-transaction routing, signed delegation replay/tamper
rejection, and process restart RTO. The takeover report also exercises a paused admitted
Git writer, stale replica rejection, a physically stopped source session,
duplicate node identities, an unusable trusted fence directory that blocks
promotion, controller restart without duplicate promotion, and old-volume
write denial. Neither report proves
cross-host storage fencing, PostgreSQL leader failover, kernel-level
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

The separate PostgreSQL PITR drill enables WAL archiving on a disposable
PostgreSQL 17 primary, takes a physical base backup and a matching offline
GitFS snapshot, then makes a later acknowledged Git push. It restores the
database to a named WAL restore point and the matching GitFS snapshot,
rotates the delegation authority before starting Rootyard, and verifies the
retained commit, object closure, permissions, token revocation, and a new
post-restore push. The later acknowledged push is intentionally outside the
restore point and is absent after recovery; this is measured data loss, not
zero RPO. The archive and snapshot are local and unencrypted, and recovery
requires manual traffic coordination. This does not establish a remote
retention policy, automated leader failover, or a supported multi-host
deployment.

The disk-pressure drill runs the real Rust service and native Git in a
rootless Docker container with a private executable tmpfs for its repository
volume. The mount is sized from the supplied executable plus headroom because
the service keeps a durable hook copy of itself under the data volume; this
keeps the check valid for large debug binaries as well as release binaries. It
fills that volume until the kernel returns ENOSPC,
checks that the attempted Git push fails without moving the acknowledged
ref, removes the filler, then fetches, runs native `git fsck`, and retries the
push. It cannot exhaust the shared workspace disk. The test covers one
small local repository and does not prove hardware-full, power-loss, or
multi-host behavior.

The Kafka test uses the Apache Kafka 3.9.1 binary distribution and creates a
disposable KRaft broker with a TLS listener and SASL/PLAIN authentication.
Its client checks reject the wrong CA, hostname, and password. Rootyard then
publishes real wake messages after Git pushes, continues to acknowledge Git
operations while the broker is stopped (PostgreSQL remains authoritative),
and publishes another wake after the broker restarts. This verifies the local
encrypted dependency and reconnect path, but not a multi-broker Kafka cluster
or a remote Kafka failover. The test distribution can be obtained from
`https://archive.apache.org/dist/kafka/3.9.1/kafka_2.13-3.9.1.tgz`.

## CI pin sidecar handoff during online migration

The supported native migration mode moves the Git repository, its journal
sequence *and* the repository's `ci-pins/<repo>` sidecars. The sidecar image is
captured together with the drained ref manifest and journal sequence, then
transferred inside the authenticated snapshot/delta frame. The target validates
the exact tenant (`owner_id`), repository, job id, target object id, object
format, source storage generation, operation id, ref digest and journal
sequence. It also verifies every `refs/rootyard-ci/jobs/*`, backup and snapshot
root accounted for by the bundle, rejects symbolic/unmanaged CI roots, and
requires that a `.pinned.json` receipt is byte-identical to its intent.
Symlinked, non-canonical, foreign-tenant or mismatched descriptors fail the
migration before any operation row or drain is created.

Sidecar files are written with `O_NOFOLLOW`, fsynced and staged in a private
directory. They are published only after the cutover transaction commits and
the target holds the new route epoch, fencing token and storage generation.
Publication takes the same repository exclusive lease/publication/maintenance
guard as a normal pin, revalidates the committed operation manifest and route
before and after the swap, and merges every legitimate new-generation intent
and receipt accepted on the new primary instead of replacing the live
directory with the old source image. The source releases its cutover guard
immediately after the cutover transaction and retired-source marker commit,
before the finalize RPC, because holding the same database advisory key across
the request would self-deadlock the target's exclusive finalize. Until a
non-empty source image has actually published, fresh pin issuance for that
repository returns a bounded `503` retryable handoff response rather than
reporting the staged old roots as unmanaged corruption; a repository with no
pre-existing CI roots may accept a fresh pin, which finalize must merge. A pending marker transition is not a
reason to bypass that guard: the internal finalize path may complete only the
exact committed operation while ordinary new writes are blocked by the same
fence, so it cannot deadlock its own recovery. The directory swap uses
`RENAME_EXCHANGE` on Linux with a journaled fallback and startup reconciliation
of interrupted `.stage-`/`.retired-` names. A master/standby still verifies the
whole transferred repository and sidecar closure before the replication
operation becomes `verified`; a stale, corrupt, empty or partial target can
never satisfy that condition. If the source dies after committing the cutover,
both the pending marker transition and the staged sidecars are republished by
startup reconciliation on their respective volumes. A durable per-operation
publication receipt makes a lost finalize response idempotent instead of a
permanent conflict. A retry tolerates files legitimately released after
publication only when their retained CI root is also gone; it never recreates
released intents or receipts. Startup staging cleanup retains uninspected
orphans and removes only staging whose exact operation row proves it aborted or
belongs to another target. The sidecar threat model is a trusted single host:
repository owners and the service UID are trusted, and intent/receipt/publish
files are opened with `O_NOFOLLOW` inside service-owned directories; untrusted
shared-volume writers are not supported.

Released pins and cancelled checkout jobs are tombstones. An intent whose
retained CI root is not in the measured manifest is omitted instead of being
resurrected, and a receipt without its root fails closed. The old-generation
intent and receipt are preserved verbatim on the new primary only as retention
evidence and cannot authorize a checkout under the new generation: a fresh
job/attempt must issue a fresh pin, and cancelled or released jobs stay denied. Startup reconciliation enumerates every operation
for the target node instead of a small completion window; it retains staged
bundles for copying, verified and completed operations, resolves an exact
operation row before cleanup, and deletes only staging proven aborted or
foreign. It never treats absence from a bounded query as permission to delete
the only surviving copy of a committed sidecar image.

## Opt-in native crash-phase hooks

The test binary supports bounded fault markers at transfer-copy, target
receive/verify, final drain/delta, cutover commit/publish, sidecar publish,
startup reconciliation and controller takeover boundaries. They are inert
unless both `ROOTYARD_TEST_FAULT_ALLOW=1` and `ROOTYARD_TEST_FAULT=<phase>` are
set. A hook only writes a diagnostic marker under `<data>/.native-test-faults`
and can then self-deliver SIGKILL (`ROOTYARD_TEST_FAULT_ACTION=kill`) or pause a
bounded time (`pause`). It does not accept caller-supplied receipts, does not
write route, repository, journal or sidecar state, and cannot forge a
production outcome. The native matrix in
`tests/cluster_migration_sidecar_native.py` creates its own disposable
PostgreSQL database, kills real source and target processes at those durable
boundaries, restarts them, resumes duplicate requests, and verifies every
acknowledged commit and retained root with stock `git push`, `git fetch` and
`git fsck --full --strict`, exactly one writer after cutover, and a non-writer
old source after the true drain fence. This remains a one-host, one-
PostgreSQL-authority deployment; it does not establish physical cross-host
fencing, power-loss durability or multi-host leader election.
