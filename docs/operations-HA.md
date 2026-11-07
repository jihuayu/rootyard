# Operations: supported external PostgreSQL HA with Patroni, etcd and HAProxy

Status: reference profile implemented and exercised natively on one Linux
host by `tests/cluster_patroni_native.py`. It is a supported *external* HA
stack (Patroni + etcd + HAProxy), not a custom in-process consensus protocol,
and it is not certified for production on the local virtual machine used for
the acceptance run (no hardware watchdog, one physical host).

## Roles and components

| Component | Reference implementation | Evidence in this repository |
| --- | --- | --- |
| DCS / leader election | etcd v3.5.x, 3 members, mutual TLS | 3 real members started by the native test |
| HA controller / fencing of the database role | Patroni 4.x | automatic promotion after a hard crash, no manual promote |
| Stable application endpoint | HAProxy 3.x routing on Patroni REST role health | Rootyard stays connected to one host:port across a failover |
| Metadata | PostgreSQL 17, TLS `verify-full` + SCRAM-SHA-256 | `deployment/ha/render.py` output and native checks |
| Application data | Rootyard GitFS volume | retained per node; this profile does not replicate the Git volume |
| Backup / new-deployment restore | `rootyard backup --offline` + `rootyard restore --isolated` | real verified closure restored into a fresh database and data directory; format/schema read from the manifest |

The renderer is `deployment/ha/render.py`; it consumes a cluster spec and a
private secrets file and emits `patroni-<node>.yml`, `etcd-<node>.args`,
`haproxy.cfg`, `rootyard.env` and the Patroni `post_bootstrap` script. See
`deployment/ha/README.md` for the inputs and the exact command.

## Reproducible secure configuration

`render.py` refuses to render a configuration that would silently weaken the
deployment:

- PostgreSQL server TLS is mandatory and the service connection uses
  `sslmode=require` together with `ROOTYARD_PG_CA_PEM`, which Rootyard treats
  as full certificate **and hostname** verification (it rejects
  `sslmode=disable` when a CA is configured). The reference `rootyard.env`
  never carries a plaintext fallback.
- `pg_hba` allows only `hostssl` lines, rejects `hostnossl` explicitly, and
  uses SCRAM-SHA-256. The test proves plaintext and untrusted-CA connections
  are rejected at runtime.
- Replication uses a separate `repl` role with only `REPLICATION`; the
  superuser and the Rootyard service role never replicate. Replication
  connections are forced to `sslmode=verify-full` with the deployment CA.
- etcd requires a client certificate signed by the deployment CA
  (`--client-cert-auth`, `--peer-client-cert-auth`); Patroni is configured with
  DCS `https`, CA and client certificate/key. A client without a certificate
  is rejected (checked natively).
- The Patroni REST API is bound to loopback (network access control) and
  management endpoints require basic authentication; an unauthenticated
  management request is rejected with 401 (checked natively). Patroni's
  read-only health/GET endpoints are unauthenticated by design, so
  loopback-only binding is the security boundary for those; HAProxy sends the
  basic credential on its role checks anyway.
- HAProxy routes only on Patroni role-health `GET /primary` / `GET /replica`
  checks. The proxy sends Basic credentials, but Patroni health GETs are
  unauthenticated by design, so the loopback-only binding is the actual access
  boundary. A node that is not the elected primary is never used for the
  write endpoint, and stale client sessions to a failed node are closed
  (`on-marked-down shutdown-sessions`) so the application pool reconnects to
  the promoted node on the same address. HAProxy 3.0 has no `init-state`
  keyword, so a server is assumed UP until its first role checks fail: start
  the endpoint only once Patroni has an elected leader, and the harness
  refuses to issue a write until role routing has been stable for several
  consecutive checks. The replica endpoint is verified with TLS/SCRAM to
  serve only a standby (`pg_is_in_recovery()`) and never the primary.
- Every password must be a distinct, non-placeholder value of at least 16
  characters; shared or weak credentials are rejected at render time.

## Production fencing and watchdog requirement

Patroni + etcd provide leader election and *database-role* fencing: only the
leader accepts writes, and a leader that loses the DCS lease demotes itself.
That is not sufficient by itself for every failure mode. The production
profile therefore **requires** a real watchdog device that the kernel watchdog
subsystem has registered:

```json
{"environment": "production", "watchdog": {"device": "/dev/watchdog", "safety_margin": 5}}
```

`render.py` validates the configured path as a character device and then
requires its kernel major/minor to appear under `/sys/class/watchdog/*/dev`
with non-empty `identity` metadata. `/dev/null`, `/dev/urandom` and any other
software character device are rejected. The validator only reads metadata:
it never opens the device or issues watchdog ioctls, because opening/arming a
watchdog during a mere configuration check can reset the machine. This is a
configuration gate, not physical hardware qualification.

Any kernel-registered watchdog identity, including a kernel software watchdog
such as `softdog`, passes this configuration gate. That is not hardware
qualification: software watchdogs are emulated timers, can trigger a reboot
only while the kernel and scheduler are healthy, and are not a substitute for a
hardware watchdog that resets a wedged host. Use a real hardware/BMC watchdog
for production fencing; the hardware positive remains unqualified here. The acceptance host has no
registered watchdog, so this run validates the gate but does **not** certify
production fencing. For real production use also supply:

- actual physical hosts with independent power/network failure domains and a
  real watchdog (or a supported fencing agent) per node;
- a private management network, certificate rotation, and etcd RBAC (mTLS is
  the minimum implemented and tested here);
- an HAProxy pair/VIP or a load balancer for the stable endpoint itself, since
  a single local HAProxy process is a single point of failure;
- replicated storage for the Rootyard GitFS volume. Patroni protects
  PostgreSQL metadata; it does not replicate the Git object store.

## Failover semantics verified natively (single-host scope)

The native test starts three etcd members (mutual TLS), three Patroni-managed
PostgreSQL 17 nodes (TLS + SCRAM, `synchronous_mode: true`,
`synchronous_mode_strict: true`, `synchronous_commit: remote_apply`) and one
HAProxy stable primary endpoint. Replica bootstrap passes
`pg_basebackup --checkpoint=fast`; the pg_basebackup default (spread)
would delay the first standby by up to `checkpoint_timeout`. Rootyard serves Git through that endpoint.

1. Real Git clone/push/fetch/fsck workload records every acknowledged OID and
   its acknowledgement time.
2. The complete old primary node is hard-killed: the Patroni process group and
   the PostgreSQL postmaster process group/session are both killed, including
   backends, so no unfenced writable PostgreSQL is left behind. The test
   asserts the old PostgreSQL port is closed and no node process survives.
3. Patroni automatically elects and promotes a successor. No `pg_ctl promote`,
   `patronictl failover` or other operator step is executed. The test records
   the promotion log lines and the elected leader.
4. The stable endpoint reconnects to the successor on the same host:port, the
   existing Rootyard process (same PID, no restart) becomes ready again and
   serves a new push; every pre-crash acknowledged OID is present in history
   and a fresh clone passes `git fsck --full --strict`. RPO and RTO fields in
   the report are measured from those timestamps.
5. Token revocation, tenant isolation and the durable outbox worker backlog
   are rechecked on the promoted cluster.
6. DCS quorum loss: two of three etcd members are stopped. The test keeps a
   per-sample history of every node's actual PostgreSQL role and Patroni REST
   status for the whole loss window, and fails immediately if any standby
   becomes a primary. During the old leader's still-valid lease, real writes
   may legitimately continue; that interval is measured and reported, not
   labelled unsafe. Once the old primary is observed read-only/stopped, the
   test keeps the quorum absent for a bounded five-second verification window
   and requires every real durable no-op write probe against the fixture
   application database to be rejected, failing immediately on any accepted
   write. Patroni's cached REST view is recorded but not trusted. When the
   quorum returns, Patroni automatically re-acquires its session lock; the test
   waits for stable endpoint routing and records the actual recovered primary
   (which need not be the previous old primary) before accepting a new write.
   No manual promotion is performed.

The same-host process scope is reported explicitly. Killing processes on one
host is not power loss, not a kernel network partition, and not evidence of
cross-host fencing.

## Backup and new-deployment restore

After the failover and quorum-loss drills the test stops the application
writer, takes a real `rootyard backup --offline` closure through the stable
endpoint, verifies it with `backup-verify`, and records the archive format and
schema from the verified `manifest.json` (the certified local binary currently
produces format 7/schema 131; newer composed binaries must report their own
observed values). It then
restores it with `rootyard restore --isolated --trust-backup` into a *fresh*
PostgreSQL 17 cluster and a *new* private data directory. No Rootyard ingress
exists for the restored authority until these offline checks pass:

- restored metadata row counts equal the source counts;
- every pre-backup acknowledged OID exists and `git fsck --full --strict`
  passes; the post-boundary write is intentionally absent (measured disaster
  RPO, not zero);
- the delegation authority incarnation is preserved by the restore and then
  rotated before ingress so old delegation tokens cannot be replayed;
- the delivery worker drains the retained outbox against the restored
  authority;
- permissions, read-only tokens, revocation and a new Git push are exercised
  on the restored deployment.

### Backup format/schema compatibility (including Pando)

The acceptance derives format and schema from the verified manifest instead of
hardcoding them. The certified local binary produces format 7/schema 131 today.
A composed binary that produces Pando schema132/backup format8 must be recorded
honestly from its own verified manifest and must pass the same gates: untouched
`backup-verify`, exact ref/OID-map equality, pre-boundary ACK survival, absence
of the post-boundary OID, retained delegation/revocation/worker checks, and the
same trusted binary for backup and restore. These gates are never weakened to
admit a newer format, and this worker does not claim a schema132/format8 pass
until the composed binary is actually exercised.

Cutover is a deliberate operator action: the reference profile never starts
the restored deployment beside the old writer automatically.

## Reproduce

```sh
# task-owned dependencies (TLS-verified downloads into a user directory)
python3 -m pip install --target "$VENDOR/python" "patroni==4.0.4" "psycopg[binary]" pyyaml python-etcd
# etcd v3.5.17 tarball + SHA256SUMS, HAProxy package extracted (not installed)

python3 tests/cluster_patroni_native.py \
  --binary /absolute/path/to/rootyard \
  --report /tmp/ha43/cluster-patroni.json
```

The harness stores no credentials in the repository or report, uses ports
>= 26000 only, and keeps all data directories outside the checkout. Required
dependencies are documented in `deployment/ha/README.md`.

## Untested boundaries

- One physical host for all etcd and PostgreSQL nodes; no cross-host, rack,
  zone, power-loss or kernel network-partition claim.
- No hardware watchdog is present; the production watchdog/fencing gate is
  validated as configuration only.
- HAProxy is a single local process; its own HA/failover is out of scope.
- The Rootyard GitFS volume is local to the node; only metadata is protected
  by PostgreSQL synchronous replication. A Git volume loss needs the restore
  path above.
- etcd RBAC users/roles are not enabled (mutual TLS client authentication is);
  multi-broker Kafka and other dependencies are unchanged and not covered.
