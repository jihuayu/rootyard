# Distributed operations acceptance (#43 / #44)

This document records what the repository actually runs for the distributed
deployment and measurement issues. It is a functional single-host reference
profile with external PostgreSQL and Kafka, not a certified multi-host HA
product.

## Runnable roles

| Role | Command | Storage | Notes |
| --- | --- | --- | --- |
| data/API node | `rootyard serve` | own `ROOTYARD_DATA_DIR` | Git and HTTP ingress; shard control operations run on these processes |
| delivery worker | `rootyard worker` | none | PostgreSQL-only outbox consumer |
| read mirror | `rootyard serve-mirror` | dedicated mirror volume | read-only clone service |
| offline operator | `rootyard migrate`, `backup`, `restore`, `pando-transition` | owning volume only | never runs beside a live writer |

There is no standalone control-plane, runner, or workspace HTTP process in the
binary. A deployment must not claim those roles as separately supported. The
reference launcher is `deployment/local_cluster.py`; inputs and secret-file
requirements are in `deployment/local-cluster.md`.

## Security inputs actually verified

`tests/cluster_local_profile_native.py` provisions real dependencies and fails
before starting Rust processes when an identity or credential is wrong:

- PostgreSQL 17 over `sslmode=require` with a CA file, hostname verification,
  SCRAM-SHA-256 users, `hostssl ... scram-sha-256`, and an explicit
  `hostnossl ... reject` rule.
- Kafka KRaft over `SASL_SSL` with a separate login and consumer group for each
  data node and the worker, a CA truststore, hostname verification, and an
  existing wake topic.
- Distinct PostgreSQL and Kafka identities for the migrator, data nodes, and
  worker. A wrong Kafka role password is rejected during preflight and the
  failed attempt leaves no client properties behind.
- A base64 32-byte-or-larger cluster HMAC key, private `0700` state/fence
  directories, and `0600` service environment files.

`tests/cluster_tls_native.py` and `tests/cluster_kafka_tls_native.py` add the
negative checks: wrong PostgreSQL password, wrong CA, hostname mismatch,
explicit `sslmode=disable`, and wrong Kafka CA/hostname/password.

## Reproducible acceptance commands

```sh
python3 tests/cluster_tls_native.py --binary <binary> --report evidence/cluster-tls.json
python3 tests/cluster_kafka_tls_native.py --binary <binary> --kafka-home <kafka> --report evidence/cluster-kafka-tls.json
python3 tests/cluster_local_profile_native.py --binary <binary> --kafka-home <kafka> --report evidence/cluster-local-profile.json
python3 tests/cluster_workload_native.py --binary <binary> --report evidence/cluster-workload-integration.json
python3 tests/cluster_pg_streaming_native.py --binary <binary> --report evidence/cluster-pg-streaming.json
python3 tests/cluster_pg_pitr_native.py --binary <binary> --report evidence/cluster-pg-pitr.json
python3 tests/cluster_takeover_native.py --binary <binary> --report evidence/cluster-takeover-run.json
python3 tests/cluster_partition_native.py --binary <binary> --report evidence/cluster-partition.json
python3 tests/cluster_disk_pressure_native.py --binary <binary> --report evidence/cluster-disk-pressure.json
python3 tests/cluster_operations_gate.py --evidence-dir evidence --report evidence/cluster-operations-gate.json
```

Every report produced by these tests carries `measurement_kind:
native_execution`, `simulated_fields: false`, the source commit, binary and
harness SHA-256, tool versions, hardware, topology, dataset, workload, and
explicit limits. `tests/cluster_operations_gate.py` rejects reports without
that provenance, a binary/source mismatch, a dirty source tree, or missing
measured fields. The synthetic `/api/shards/benchmark` receipt is labelled
`status: simulation_only` and can never satisfy the gate.

## Acceptance mapping

| Issue criterion | Evidence | Observed | Boundary |
| --- | --- | --- | --- |
| #43.1 bring up reference deployment; real cross-node Git/checkout; encrypted authenticated deps | `cluster-local-profile.json`, `cluster-tls.json`, `cluster-kafka-tls.json` | 2 real Rust data processes + PG-only worker; push through non-owner ingress; owner clone and routed browse return the same acknowledged OID; Kafka offset advances; wrong CA/hostname/password rejected | one trusted Linux host; single PostgreSQL and single Kafka broker |
| #43.2 PostgreSQL and storage-node failover under load; no double writer or false ACK | `cluster-pg-streaming.json`, `cluster-takeover-run.json`, `cluster-partition.json` | synchronous `remote_apply` primary stopped while native reads and writes run; manual standby promotion; acknowledged writes survive; stale replica rejected; admitted Git writer paused then fenced; old session killed and restart blocked; source-only TCP break fails closed | manual promotion, local process-session fence, no DCS or cross-host fencing |
| #43.3 restore metadata and storage in a new deployment; commits, job revocation, permissions, workers | `cluster-pg-pitr.json` | WAL archive + base backup + matching GitFS snapshot; restore to named point; new data volume/endpoint; delegation authority rotated; retained commit/fsck pass; token revocation and foreign-tenant denial rechecked; delivery worker drains retained outbox before ingress reopens; later acknowledged write intentionally absent | local unencrypted archive and manual traffic restart; not zero-RPO HA |
| #44.1 reports identify source/binary/tools/topology/dataset/workload/hardware/raw evidence; simulation cannot gate | all seven native reports + `cluster-operations-gate.json`; `benchmark.rs` simulation label | provenance and raw workload records validated; simulated benchmark is visibly separate | no additional physical hosts are configured |
| #44.2 physically remove a retained object or stop the target node; readiness/reachability assertions fail | `cluster-workload-integration.json` | owner process SIGKILL during traffic: routed read/browse return 502; disposable live serving-volume repository is stopped, acknowledged/pinned loose object removed, restarted, stock fetch and native fsck fail; exact bytes restored, fsck passes, fetch/clone recover | single host; no hardware/power-loss claim |
| #44.3 RPO/RTO from actual acknowledged operations and observed recovery | `cluster-workload-integration.json`, `cluster-pg-streaming.json` | every acknowledged OID is re-fetched after restart; RPO 0 for measured workloads; read/write RTO measured from stop to recovered operation; write load records acknowledged vs failed pushes | operational samples, not an SLA or capacity plan |
| #44.4 readiness/implementation docs match the real run and list untested boundaries | this document, `TEST_READY.md`, `docs/cluster-local-process-fence.md` | model-tier results are marked historical; native reports and limits are linked | delivery-owned status files are updated separately |

## RPO/RTO assumptions

- RPO is zero for the measured synchronous PostgreSQL path only because
  `synchronous_commit=remote_apply` and the Git volume is retained on the same
  host. Losing that volume is not covered by the PostgreSQL drill.
- PITR intentionally loses every acknowledged write after the named restore
  point; that is measured data loss, not zero RPO.
- RTO numbers in the reports are observed wall-clock times from fault injection
  to the first successful read or write. Manual operator steps and client
  reconfiguration dominate in a real incident; do not publish them as an SLA.
- A falsely acknowledged write is a gate failure. Disk pressure, process loss,
  and primary loss runs assert that the acknowledged ref does not move.

## Failure and restore ordering

1. PostgreSQL: stop/detect primary, observe read/write failures, promote the
   synchronous standby, restart the service against the new endpoint, verify
   the acknowledged OID is in history, and reject writes until ready.
2. Storage node: expire the old lease, verify replicated refs and full object
   closure, fence the old process session/volume, compare-and-swap the route,
   verify the target with `git fsck`, then accept writes. A stale or ambiguous
   target must remain read-only. This profile uses a local process session, not
   cross-host storage fencing.
3. PITR: stop writers, take a base backup, archive WAL, snapshot the matching
   GitFS volume, restore PostgreSQL to a named point, restore the matching
   snapshot into a **new** data directory/endpoint, rotate the delegation
   authority, run the delivery worker against the restored authority, verify
   commits, token revocation, permissions, outbox and fsck, then reopen ingress.
   Never point a restored volume at a live old deployment.

## Upgrade and rollback

Binary upgrades require exclusive ownership of each data volume; stop the old
writer, keep a matched database/volume backup, run the new binary, and verify
`/health/ready`, Git fetch/push and `git fsck` before opening traffic. Rollback
of a schema/data change needs a matched restore, not only the old binary.
Pando cutover/rollback and abandoned-drain recovery are offline commands and
must follow `deployment/local-cluster.md`.

## Observability

Use `/health/live`, `/health/ready`, the authenticated shard route/failover
APIs, `/metrics` (where enabled), `rootyard-shard-benchmarks.json`, the
repository receipt, PostgreSQL replication state, `event_deliveries`, and the
process logs retained under the private state directory. The measurement
reports deliberately never contain credentials.

## Untested boundaries

- No second physical host, cross-host storage fencing, or network-namespace
  partition is available in this environment.
- PostgreSQL promotion is manual and has no DCS/elected leader or automatic
  application reconfiguration.
- Kafka is a single KRaft broker; multi-broker failover is untested.
- The PITR archive/snapshot is local and unencrypted; remote retention and
  cloud object-store restore are out of scope here.
- Disk pressure uses a private container tmpfs, not a hardware disk or
  power-loss failure.
- General workload scaling, single-hot-repository limits, cache eviction for
  CI mirrors, and concurrent-GC-under-load matrices are not exhaustively
  measured by the 24-push native tier test.
