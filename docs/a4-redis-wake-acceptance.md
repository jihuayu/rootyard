# A4 Redis wake external acceptance design

Status: design checkpoint only. The production wiring and source-level guards are
implemented, but the real PG17/Garage/Redis A4 acceptance described here has not
been implemented or executed in this worktree. No native service, Cargo build or
remote CI result is claimed.

## Why a separate harness

The existing generic cross-process harness owns a GitFS `serve` repository and
its `audit-log,ref-index` deliveries. The existing A4 native case
(`tests/decision_subset_support/cases_f.rs`) exercises the internal core facade
and calls `events::worker_once_with_lease_scoped` directly. Neither drives the
actual `serve-blob` HTTP/stock-Git producer through Redis to an external A4
worker.

The acceptance must therefore keep the real `serve-blob` fixture but replace its
embedded wake path with the explicit A4 topology:

- producer: `rootyard serve-blob` with
  `ROOTYARD_A4_WORKER_MODE=external` and
  `ROOTYARD_A4_WAKE_TRANSPORT=redis`; external mode removes the embedded
  local consumer so it cannot win the healthy or fallback claim;
- subscriber: `rootyard worker` with
  `ROOTYARD_WORKER_SCOPE=a4-target-audit` and
  `ROOTYARD_A4_WAKE_TRANSPORT=redis`;
- one owned loopback `RedisPartitionRelay` in front of a disposable owned Redis;
- one owned PostgreSQL schema and the existing Garage/S3 Blob profile;
- the real stock Git client over the Smart-HTTP route.

## Proposed files and entry points

| File | Responsibility |
| --- | --- |
| `tests/a4_redis_wake_partition.py` | New opt-in acceptance script. Reuses `BlobOnlyHarness`/`NativeProfile`/`check_blob_profile` from `tests/blob_only_service.py`, `OwnedRestoreRedis` from `tests/backup_recovery_cache.py`, `RedisPartitionRelay` from `tests/redis_partition_relay.py`, and `build_binding` for the source/binary receipt. |
| `tests/test_a4_redis_wake_partition.py` | Pure unit tests for the new script's wake-timing predicate, report shape and cleanup ordering, modeled on `tests/test_cross_process_partition.py`. It must not need PG/Redis/S3. |
| `tests/blob_only_service.py` | Reused fixture only. Do not change its case list or default gate; the new script imports its `BlobOnlyHarness`, `NativeProfile`, `check_blob_profile`, `parse_push`, `push_success` and `build_report`-style helpers. |
| `tests/cross_process_partition.py` | Reused timing/partition pattern: `until`, `publishes`, `subscriber_count`, `healthy_push`, `prepare_outage`, `heal_endpoint`, fixed-poll deadline assertions. Do not modify its generic cases. |
| `tests/redis_partition_relay.py` | Reused byte-transparent cut/refuse/heal relay. |
| `tests/backup_recovery_cache.py` | Reused `OwnedRestoreRedis` start/stop/identity/command helpers. |
| `src/standalone.rs`, `src/dispatch.rs`, `src/main.rs` | Production entry points already implemented: `Settings::standalone_from_env`, `Settings::a4_target_audit_from_env`, `ROOTYARD_WORKER_SCOPE=a4-target-audit`, and the shared publisher stop token. |

The script is invoked directly, never added to an existing CI gate:

```sh
ROOTYARD_TEST_DATABASE_URL=... \
ROOTYARD_TEST_REDIS_SERVER=/path/to/redis-server \
ROOTYARD_BLOB_*=<owned Garage/S3 profile> \
ROOTYARD_GIT=/path/to/trusted/git \
  python3 tests/a4_redis_wake_partition.py \
    --binary target/debug/rootyard \
    --git /path/to/trusted/git \
    --expect-commit <source-commit> \
    --report test-results/a4-redis-wake.json
```

The script must use the existing attested-binary receipt and random owned schema,
and must refuse to run against a shared/production Redis, Blob bucket or schema.

## Required case sequence

One repository and one external A4 worker, with the worker poll interval longer
than the observation window:

1. Start the owned Redis and the relay. Start `serve-blob` with
   `ROOTYARD_A4_WORKER_MODE=external`, the A4 producer variables and a channel
   such as `rootyard:a4:test:<schema>`. Start the A4 worker with the same
   endpoint/channel and `ROOTYARD_WORKER_POLL_MS` set well above the case
   deadline; assert both processes are the expected executable. Assert the
   producer has no embedded target-audit consumer by checking the subscriber
   count and by proving delivery occurs under the external worker's lease owner.
2. Wait until `PUBSUB NUMSUB` reports one subscriber and the relay has forwarded
   its connection. Confirm the initial subscription catch-up scan completed.
3. Create a repository through the real `POST /api/repos` route, clone with stock
   Git, commit, and push over real Smart HTTP. Capture the acknowledged OID and
   the producer `PUBLISH` counter before the push.
4. Assert a real publish happened through the relay before the next possible
   periodic poll, the worker scan completed, and the target audit effect landed
   exactly once. Assert terminal/ref/gate, audit outbox consumer set, and the
   absence of legacy projection/jobs (queries below).
5. Send repeated fixed `v1` hints on the A4 channel (a fixture-side `PUBLISH`,
   not a product producer) and assert the hint is coalesced or causes only extra
   PG scans: no second audit effect, no second terminal, no outbox mutation.
6. Cut the relay. Push again. Assert the push is still acknowledged and durable;
   the worker has no Redis wake; the fixed PostgreSQL ticker alone delivers after
   the configured poll deadline. Assert the Redis publish counter did not advance
   through the cut relay and the relay refused reconnects.
7. Heal the relay. Assert the existing worker resubscribes at the same endpoint,
   performs a catch-up scan, and a subsequent push is delivered by a real wake
   before the next poll deadline.
8. For every stage, read back with stock Git (`ls-remote`, clone, `fsck --full
   --strict`) and compare the durable rows to the pre-hint snapshot. Unauthorized
   and read-only pushes must remain refused without changing refs/terminal.

## Durable assertions

Use read-only SQL through the existing harness `sql()` helper. The exact target
evidence and only-once checks should at minimum cover:

```sql
-- exactly one fresh target-audit operation/terminal per push
SELECT outcome, evidence->>'kind', evidence->>'authority'
  FROM git_operations WHERE id=$operation_id;
SELECT count(*) FROM ref_store_core_events
  WHERE repository_id=$repo AND operation_id=$operation_id;
SELECT count(*) FROM ref_store_core_refs
  WHERE repository_id=$repo AND ref_name=$ref AND oid=$oid;
SELECT revision FROM ref_store_core_gates WHERE repository_id=$repo;
SELECT state, terminal_result FROM ref_store_operations
  WHERE repository_id=$repo AND operation_id=$operation_id;

-- one audit-log delivery only; no legacy ref-index/projection work
SELECT DISTINCT consumer FROM event_deliveries d
  JOIN outbox_events e USING(event_id) WHERE e.operation_id=$operation_id;
SELECT count(*) FROM audit_events a JOIN outbox_events e USING(event_id)
  WHERE e.operation_id=$operation_id;
SELECT count(*) FROM repository_ref_projection WHERE repository_id=$repo;
SELECT count(*) FROM ref_cas_projection_jobs;

-- holds/roots remain the durable authority and are not moved into Redis
SELECT count(*) FROM artifact_holds WHERE repository_id=$repo AND operation_id=$operation_id;
SELECT count(*) FROM ref_store_core_pack_memberships WHERE repository_id=$repo;
```

The test must also verify auth/refusal behavior with a read-only token and an
outside/unauthorized actor, and must keep the existing A4 root/hold assertions in
the post-commit snapshot rather than inventing SQL rows. Redis key contents are
never used as evidence of authority; the only Redis evidence is the fixed hint
counter, subscriber count and relay forwarding.

## Partition and duplicate boundaries

- The timing predicate is the same as `RedisPartitionHarness.healthy_push`: a
  delivery that occurs only after the next poll deadline is not counted as a
  wake. The worker must be started with a poll interval much larger than the
  healthy-push deadline.
- Duplicate/replayed hints and duplicate `PUBLISH` frames may add scans only.
  They must not add `audit_events`, terminals, outbox rows, refs, holds or roots.
- A cut relay must not fail the push or change durable state. A healed relay must
  not require restarting the worker.
- The worker resubscription acknowledgment itself triggers a scan; the test must
  account for that catch-up scan when counting scans, as the generic partition
  harness already does.
- Cleanup must stop the worker and producer, close the relay, stop the owned
  Redis, and drop only the random schema; it must run on every failure path.

## Explicit non-goals

This design does not add Redis HA/Sentinel/Cluster, remote TLS proxying, Kafka,
multi-host PostgreSQL failover, storage fencing, broad Git routing or default
`serve` changes. It does not alter the exact cache product, A4 commit/replay
semantics or the existing `tests/cross_process_partition.py` /
`tests/cross_process_failover.py` gates. It is an opt-in acceptance script and
its pure helper tests only.
