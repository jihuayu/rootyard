# External HA reference profile (Patroni + etcd + HAProxy)

This directory renders a supported external automatic-failover configuration
for PostgreSQL metadata. It uses established components only:

- three etcd members with mutual TLS as the DCS (quorum, leader key);
- Patroni managing PostgreSQL 17 nodes with strict synchronous replication;
- HAProxy as a stable, role-health-routed PostgreSQL endpoint.

The profile is exercised end-to-end by
`tests/cluster_patroni_native.py` and documented in
[`docs/operations-HA.md`](../../docs/operations-HA.md). The native run is
single-host and has no hardware watchdog, so it is not a production
certification.

## Inputs

`render.py` takes two JSON files:

`cluster.json` (no secrets, may be committed):

```json
{
  "environment": "lab",
  "scope": "rootyard-ha-reference",
  "pg_bin_dir": "/usr/lib/postgresql/17/bin",
  "postgres_host_ip": "10.20.30.40",
  "nodes": [
    {"name": "pg1", "pg_port": 26031, "rest_port": 26021,
     "data_dir": "/srv/rootyard/pg1", "socket_dir": "/run/rootyard/pg1"}
  ],
  "etcd": {
    "cluster_token": "rootyard-ha",
    "server_cert": "/etc/rootyard/pki/server.crt",
    "server_key": "/etc/rootyard/pki/server.key",
    "client_ca": "/etc/rootyard/pki/ca.crt",
    "client_cert": "/etc/rootyard/pki/client.crt",
    "client_key": "/etc/rootyard/pki/client.key",
    "peer_ca": "/etc/rootyard/pki/ca.crt",
    "peer_cert": "/etc/rootyard/pki/peer.crt",
    "peer_key": "/etc/rootyard/pki/peer.key",
    "nodes": [
      {"name": "etcd1", "client_port": 26001, "peer_port": 26011,
       "data_dir": "/var/lib/etcd/etcd1"}
    ]
  },
  "tls": {
    "ca": "/etc/rootyard/pki/ca.crt",
    "server_cert": "/etc/rootyard/pki/server.crt",
    "server_key": "/etc/rootyard/pki/server.key"
  },
  "haproxy": {
    "primary_port": 26040,
    "replica_port": 26041,
    "stats_socket": "/run/rootyard/haproxy.sock",
    "health_user": "haproxy-health"
  },
  "rootyard": {
    "database": "rootyard_ha",
    "user": "rootyard",
    "bind": "127.0.0.1:26050",
    "data_dir": "/srv/rootyard/data"
  },
  "synchronous": {
    "ttl": 20, "loop_wait": 2, "retry_timeout": 3,
    "synchronous_commit": "remote_apply",
    "synchronous_mode": true, "synchronous_mode_strict": true
  },
  "watchdog": null
}
```

All TLS keys listed above must be private files (`0600`, owned by the service account): the renderer validates CA, server, DCS client/peer and etcd server cert/key inputs and rejects missing, group/other-accessible keys.

`secrets.json` (mode `0600`, never committed):

```json
{
  "superuser_password": "...",
  "replication_password": "...",
  "rootyard_password": "...",
  "patroni_rest_user": "patroni-rest",
  "patroni_rest_password": "...",
  "haproxy_health_password": "..."
}
```

All passwords must be distinct and at least 16 characters of
`[A-Za-z0-9_-]`. Three etcd members and at least two Patroni PostgreSQL nodes
are required. `postgres_host_ip` is the non-loopback address Patroni
advertises for PostgreSQL (replication uses `verify-full` against its SAN).

Production mode additionally requires a real watchdog that the kernel
watchdog subsystem registered:

```json
{"environment": "production", "watchdog": {"device": "/dev/watchdog", "safety_margin": 5}}
```

The validator reads only metadata: the path must be a character device whose
major/minor appears under `/sys/class/watchdog/*/dev` with a non-empty
`identity`. `/dev/null`, `/dev/urandom` and any device not registered by the
kernel watchdog subsystem are rejected. The device is never opened and no watchdog ioctl is issued, so a
configuration check cannot arm a machine reset. A kernel-registered software
watchdog (for example the `softdog` module) passes this configuration gate;
the gate is not hardware qualification. Software watchdogs are emulated timers
and do not replace a hardware watchdog that resets a wedged host, so hardware
positive qualification remains separately required and is unavailable in the
local acceptance environment. Rendering is refused when the gate is not
satisfied; do not certify automatic failover on a host without working
fencing.

## Render

```sh
python3 deployment/ha/render.py --check --spec cluster.json --secrets secrets.json
python3 deployment/ha/render.py --spec cluster.json --secrets secrets.json --out /run/rootyard/ha
```

The output directory is `0700`; rendered files are `0600` because they contain
credentials. `--check` prints only a summary (no secrets).

Artifacts:

| File | Purpose |
| --- | --- |
| `patroni-<node>.yml` | Patroni configuration for one node |
| `etcd-<node>.args` | etcd argv, one argument per line (server/peer TLS files are validated as private inputs) |
| `haproxy.cfg` | stable primary/replica endpoints with Patroni role-health checks |
| `rootyard.env` | service environment (`DATABASE_URL`, CA, data dir, bind) |
| `bootstrap-app.sh` | Patroni `post_bootstrap` hook creating the service role/database |

## Backup format and schema

Backup/restore acceptance derives the archive format and migration schema from the verified `manifest.json` of the backup set; it does not hardcode format 7 or schema 131. The certified local binary currently produces format 7/schema 131. A composed binary that produces a newer format/schema (for example Pando schema 132 / backup format 8) must be recorded from its own verified manifest, and is only accepted after the same `backup-verify`, ref/OID-map, RPO and restored-authority checks pass. Backup and restore must use the same trusted binary, and these gates are never weakened to accept a newer format.

## Operate

1. Create the private data directories owned by the service account and place
   the PKI files so only etcd/PostgreSQL/Patroni can read the keys.
2. Start the etcd members with `etcd-<node>.args`. Verify quorum with
   `etcdctl --cacert ... --cert ... --key ... endpoint health` on each member.
3. Start Patroni on each node with `PYTHONPATH=<patroni> python3 -m patroni
   patroni-<node>.yml`, providing `ROOTYARD_BOOTSTRAP_DB_PASSWORD` in the
   service environment for the one-time bootstrap hook. `patroni
   --validate-config` must accept the rendered file.
4. Start HAProxy (`haproxy -f haproxy.cfg`) and confirm the primary endpoint
   reaches the elected leader before starting Rootyard.
5. Start Rootyard with `rootyard.env`. It should connect to the HAProxy primary
   port, never to a node port.
6. Use `GET /primary` (200 only on the leader) and `GET /replica` for health
   checks. Patroni health GETs are unauthenticated by design and are protected
   by the loopback-only bind; HAProxy nevertheless sends the basic-auth
   credential. Patroni management endpoints require that credential.

Upgrade/rollback and restore ordering are covered in
[`docs/operations-HA.md`](../../docs/operations-HA.md).
