# Trusted local cluster profile

`local_cluster.py` starts two or four **separate Rust data processes**, each with
its own Git volume and node identity, plus one PostgreSQL-only control worker.
It verifies PostgreSQL certificate hostname and user identity, and verifies each
Kafka SASL/TLS identity with the real Kafka client before migration or startup.
`verify` creates a real repository, pushes through a non-owner ingress, clones
from the owner, reads a ref through routed browse, and checks a broker offset
advance. This is a functional local profile, not a multi-host HA certification.

The following inputs are prepared by the operator. All files containing a
password, token, signing key, or CA path must be regular files in a private
directory, mode `0600`; the CA PEM itself is also mode `0600` in this profile.
Create the state directory mode `0700`. No secret is printed to JSON output.

| File | Required fields |
| --- | --- |
| `migrator.env` | `DATABASE_URL=postgresql://migrator:<password>@localhost:<port>/rootyard?sslmode=require`, `ROOTYARD_PG_CA_PEM=<absolute CA PEM>` |
| `node0.env`, `node1.env` (plus `node2.env`, `node3.env` for four nodes) | Each node's own PostgreSQL login URL and Kafka SASL login; fields below |
| `worker.env` | Worker-specific PostgreSQL login URL and Kafka SASL login; fields below |
| `operator.json` | `{"username":"<operator>","token":"<token>"}` from `rootyard create-user` or `create-token`; the token ID must already be granted in `cluster_operator_tokens` |

Each service `.env` contains these **literal** `NAME=value` lines; the launcher
does not execute a shell or expand variables:

```text
DATABASE_URL=postgresql://<role>:<url-encoded-password>@localhost:<pg-port>/rootyard?sslmode=require
ROOTYARD_PG_CA_PEM=/absolute/private/pg-ca.pem
ROOTYARD_CLUSTER_HMAC_KEY=<same-base64-encoded-32-or-more-random-bytes-on-all-nodes>
ROOTYARD_WAKE_TRANSPORT=kafka
ROOTYARD_KAFKA_BOOTSTRAP_SERVERS=localhost:<kafka-port>
ROOTYARD_KAFKA_TOPIC=<existing-durable-wake-topic>
ROOTYARD_KAFKA_GROUP=<unique-group-for-this-role>
ROOTYARD_KAFKA_SECURITY_PROTOCOL=SASL_SSL
ROOTYARD_KAFKA_CA_PEM=/absolute/private/kafka-ca.pem
ROOTYARD_KAFKA_SASL_MECHANISM=PLAIN
ROOTYARD_KAFKA_SASL_USERNAME=<unique-role-login>
ROOTYARD_KAFKA_SASL_PASSWORD=<role-password>
```

For a local reference database, provision a TLS certificate with a SAN matching
the hostname in every URL and use `hostssl ... scram-sha-256` with a final
`hostnossl ... reject` rule in `pg_hba.conf`; enable `password_encryption =
'scram-sha-256'`. The launcher checks TLS, certificate hostname and `current_user`
for every role. The migration account and each data/worker account must have
different login names. Currently each service calls schema migration on start,
so the database roles need shared schema-owner privileges. This is **not** a
least-privilege SQL grant profile; split runtime/migration DB permissions is
future work. Use a dedicated database, never an unrelated shared schema.

Provision Kafka with a broker TLS certificate whose SAN matches the bootstrap
hostname, SASL/PLAIN logins unique to each service role, and an existing wake
topic. Restrict broker ACLs to topic produce/consume and group access; the
profile does not provision ACLs or a broker. The wake is advisory: PostgreSQL
outbox rows remain durable and the worker polls if Kafka is unavailable.

The delivery role needs `UPDATE` on `event_deliveries` and ordinary `SELECT`
on repositories/outbox tables. Migration 129 makes
`rootyard_worker_repository_generation(uuid,name)` executable by any login, but
the SECURITY DEFINER body raises SQLSTATE 42501 unless `session_user` holds
that `event_deliveries` UPDATE privilege. No `UPDATE` on `repositories` is
needed; grant it only if you also grant the delivery table, and never make the
worker a schema owner.

```bash
python3 deployment/local_cluster.py up \
  --binary /absolute/path/rootyard --env-dir /absolute/private/config \
  --state-dir /absolute/private/state --kafka-home /absolute/path/kafka_2.13-4.4.0 \
  --operator-account /absolute/private/operator.json --nodes 2
python3 deployment/local_cluster.py verify \
  --state-dir /absolute/private/state --account /absolute/private/operator.json \
  --report /absolute/private/profile-report.json
python3 deployment/local_cluster.py down --state-dir /absolute/private/state
```

The launcher binds the data/API nodes to loopback, supplies `ROOTYARD_NODE_ID`,
separate `ROOTYARD_DATA_DIR`, `ROOTYARD_OUTBOX_WORKER=false`, and the trusted
local process-fence directory. It records exact PID/start-time/boot identities
and stops only matching process sessions; `down` preserves volumes. The worker
uses `rootyard worker`, has no Git volume, and processes the shared PostgreSQL
outbox. A control operator uses the authenticated shard APIs and the separate
`migrator.env` identity. The current binary does not provide a standalone
control HTTP role: these routes run on the data/API nodes.

A migration that fails after the source begins draining deliberately keeps the
source write-blocked. Retry `/shard-migrate` with the **same operation ID**
after repairing the destination. The source snapshot, destination install,
and source cutover use ordered PostgreSQL and local barriers; do not clear the
drain by editing SQL directly or by registering a new target volume as current.

### Pando backend transition recovery

`cutover`, `rollback` and abandoned-drain recovery are offline commands. They
open the data directory exclusively, so stop the server that owns that volume
first; a live server or another offline operator makes the command fail with
`data volume is in use`. `status` is PostgreSQL-only, read-only and safe while
the server runs, so it is the command to identify the exact fence to recover.

```bash
rootyard pando-transition status --repository <repo-uuid>
rootyard pando-transition cutover --repository <repo-uuid>
rootyard pando-transition rollback --repository <repo-uuid>
rootyard pando-transition recover-abandoned-draining   --repository <repo-uuid> --expected-transition <uuid> --expected-epoch <n>   --expected-backend <gitfs|pando> --expected-generation <n>
```

A crashed process can leave `transition_state=draining` with no live worker.
Inspect `status` and record its exact `transition_id`, `transition_epoch`,
`storage_backend` and `storage_generation`. Stop the server, then run the
recovery command while holding exclusive volume ownership. It also takes the
repository publication advisory lock, so an active publisher or transition
rejects it. It then requires every expected value to still match under
`FOR UPDATE` and moves the fence to `failed` with an operator error. It never
moves directly to `stable`. Ordinary writes remain blocked. After repairing the
original cause (object store, capacity, Git parity or HEAD), rerun the same
direction with `cutover`/`rollback`; `begin` accepts `failed`, mints a new
transition ID and epoch, and only a successful completion restores `stable`.
Do not edit `transition_state` directly.

For workspace execution, add `ROOTYARD_WORKSPACE_MOUNT_MODE=fuse` to the
corresponding node environment and provide `/dev/fuse` and a functioning user
mount namespace. A workspace mount is local to that process's namespace;
handoff/checkpoint uses the workspace API, not a shared writable Git volume.
For untrusted sandbox jobs use `ROOTYARD_SANDBOX_MODE=cgroup`, a delegated
writable cgroup v2 root in `ROOTYARD_SANDBOX_CGROUP_ROOT`, and `bwrap`. The
`dev` sandbox mode is only a local test setting. An external CI integration
runner is an HTTP client: it claims a signed, exact origin/run/checkout tuple
through the sandbox-job API; the binary has no standalone runner process. The
native workspace FUSE/Garage two-volume and signed CI sandbox suites are
separate role-acceptance evidence; `verify` itself checks Git and Kafka only.

Multi-host operation requires an HTTPS endpoint and trusted CA on every node,
plus an external placement/fencing controller that **revokes old physical
storage access before promotion**. The included local controller fences a
trusted process session on one Linux host; it cannot prove cross-host storage
revocation. Do not use local process fencing as a remote HA driver. Configure
PostgreSQL synchronous replication with acknowledged commit policy, an HA/DCS
leader with independent fencing, tested WAL archive/base backups, and restore
points paired with frozen Git volumes. The native PG streaming promotion and
PITR tests exercise those data paths, but no external HA/DCS provider is
integrated or certified by this profile.

For restore, stop ingress and workers, fence every old writer, restore the
PostgreSQL backup/WAL and matching Git volume generation, run backup
verification and offline reconciliation, rotate the cluster authority signing
incarnation, then reopen ingress. For upgrade, take a PG+Git backup pair,
quiesce writes, verify the new binary against the backup, migrate once with the
migrator account, then roll data nodes one at a time only while routing keeps
the assigned primary available. A schema migration is forward-only; rollback
requires the paired pre-upgrade PG+Git restore and authority rotation, not a
binary downgrade against a newer schema.
