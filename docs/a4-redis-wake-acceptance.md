# A4 Redis wake external acceptance

Status: the opt-in native entry point and its pure tests are implemented; no
native PG17/Garage/Redis execution is claimed in this worktree. The script binds
the executed binary to an exact clean source commit and an attested
`state-redis` build receipt, and emits the fixed report kind
`rootyard/a4-redis-wake-external-acceptance`. A real PASSED report is still
required from the owned native fixture; source inspection and the pure tests are
not a substitute.

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

## Files and entry points

| File | Responsibility |
| --- | --- |
| `tests/a4_redis_wake_partition.py` | Implemented opt-in acceptance script. Reuses `BlobOnlyHarness`/`NativeProfile`/`check_blob_profile` from `tests/blob_only_service.py`, `OwnedRestoreRedis` from `tests/backup_recovery_cache.py`, `RedisPartitionRelay` from `tests/redis_partition_relay.py`, and `build_binding` for the source/binary receipt. |
| `tests/test_a4_redis_wake_partition.py` | Implemented pure tests for source constants, wake-timing rejection, report shape/stages, preflight refusal and cleanup ordering. They need no PG/Redis/S3. |
| `tests/blob_only_service.py` | Reused fixture only. Its case list and default gate are unchanged; the new script imports its `BlobOnlyHarness`, `NativeProfile`, `check_blob_profile`, `parse_push`, `push_success` and `write_report` helpers. |
| `tests/cross_process_partition.py` | Reused timing/partition pattern: fixed-poll deadline assertions, relay cut/refuse/heal and scan-accounting discipline. Its generic cases are unchanged. |
| `tests/redis_partition_relay.py` | Reused byte-transparent cut/refuse/heal relay. |
| `tests/backup_recovery_cache.py` | Reused `OwnedRestoreRedis` start/stop/identity/command helpers and exact `build_binding` source/receipt checks. |
| `src/standalone.rs`, `src/dispatch.rs`, `src/main.rs` | Production entry points: `ROOTYARD_A4_WORKER_MODE=external`, `Settings::standalone_from_env`, `Settings::a4_target_audit_from_env`, `ROOTYARD_WORKER_SCOPE=a4-target-audit`, and the shared publisher stop token. |

The binary must carry the existing attested `state-redis` build receipt whose
`features.enabled` is exactly `["state-redis"]` and whose source commit/tree
matches the clean current checkout. It is the same receipt contract used by the
existing Redis evidence:
`cargo build --locked --bin rootyard --features state-redis --config
profile.dev.package.rootyard.strip="debuginfo" --message-format=json-render-diagnostics`.
The script refuses preflight if Redis, the S3/Garage profile, `psql`, the exact
commit or the receipt is missing. It is invoked directly, never added to an
existing CI gate:

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

The script uses the existing attested-binary receipt and a random owned schema,
and starts its own disposable Redis process behind an owned relay. The
Garage/S3 profile is required by the existing Blob harness, but its ownership
remains an operator attestation rather than a cryptographic proof; do not point
it at a shared production bucket.

## Required case sequence

One repository and one external A4 worker, with the worker poll interval longer
than the observation window:

1. Start the owned Redis and the relay, then start `serve-blob` with
   `ROOTYARD_A4_WORKER_MODE=external`, the A4 producer variables and the unique
   channel. Create the repository through the real `POST /api/repos` route,
   clone with stock Git, commit and push over real Smart HTTP before any worker
   exists. Wait three seconds and assert the target audit delivery is still
   pending and no `audit_events` row exists. This proves external placement did
   not launch an embedded local consumer.
2. Start exactly one `rootyard worker` with
   `ROOTYARD_WORKER_SCOPE=a4-target-audit`, the same endpoint/channel and a
   20-second poll. Assert `PUBSUB NUMSUB` sees one subscriber, the relay forwards
   its connection, the initial catch-up delivers the pre-worker operation, and
   the delivery claim is owned by the external worker's `application_name`.
3. Wait for the worker connection to be idle, then perform a new stock-Git push.
   Assert the producer `PUBLISH` counter and relay forwarded count both advance,
   and the external worker delivers before the next possible poll. Assert the
   terminal/ref/gate, object membership, hold/consume receipts, one `audit-log`
   delivery, one audit effect, and no legacy projection/jobs.
4. Publish repeated valid `v1` hints plus one wrong-version and one wrong-channel
   frame directly through the owned Redis. Wait for recovery, assert the
   subscriber is healthy and idle, and assert the durable snapshot and claim
   trace are identical: no second audit effect, terminal, outbox row, ref,
   hold or root.
5. Cut the relay. Wait for the subscriber to disappear and reconnects to be
   refused. Push again. Assert the push is still acknowledged and the ref is
   readable; before the next poll the audit effect is still absent and the owned
   Redis `PUBLISH` counter did not advance. Then assert the fixed PostgreSQL
   ticker alone delivers after the poll deadline, with no relay forwarding.
6. Heal the relay. Assert the existing worker resubscribes at the same endpoint,
   performs its catch-up scan and becomes idle. Before the following poll,
   perform another push and assert a real publish/forwarded increment and
   wake-delivery before that poll.
7. Attempt a push with the read-only token and with an unrelated actor; assert
   both fail, the durable snapshot is unchanged, and an authorized read-only
   clone still reproduces the latest acknowledged OID with `fsck --full
   --strict`.
8. Read back with stock Git (`ls-remote`, clone, `fsck`) and compare the durable
   rows to the pre-hint snapshot. A resubscribe catch-up scan or an embedded local
   Notify is never accepted as healthy steady-state wake evidence; each healthy
   phase requires the publish/forwarded counters and the pre-poll deadline.

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
SELECT count(*) FROM artifact_hold_consume_receipts
  WHERE repository_id=$repo AND operation_id=$operation_id;
SELECT count(*) FROM ref_store_core_pack_memberships WHERE repository_id=$repo;

-- the only A4 claimant is the distinct external process
SELECT state, app FROM test_a4_claims c JOIN outbox_events e USING(event_id)
  WHERE e.operation_id=$operation_id AND c.consumer='audit-log'
  ORDER BY c.n DESC LIMIT 1;
```

The fixture creates a bounded `test_a4_claims` trace trigger on the owned
`event_deliveries` table; it records the PostgreSQL `application_name` and lease
owner for each audit-log insert/lease/delivery. The final delivered row must name
`rootyard_a4_redis_wake_worker`, and no delivered row for the operation may name
another process. The test must also verify auth/refusal behavior with a read-only
token and an outside/unauthorized actor, and must keep the existing A4 root/hold
assertions in the post-commit snapshot rather than inventing SQL rows. Redis key
contents are never used as evidence of authority; the only Redis evidence is the
fixed hint counter, subscriber count and relay forwarding.

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

## Report contract

`--report` is required and is written atomically through the existing
`write_report` helper. The report kind is exactly
`rootyard/a4-redis-wake-external-acceptance`; the case name is exactly
`real_a4_redis_wake_external_pg_fallback`. The report carries `source_head`,
`source_tree`, `source_inputs_sha256`, `binary_sha256`, `build_receipt_sha256`
and the acceptance harness SHA-256, plus the fixed limitations list. It never
contains a DSN, token, Redis URL, S3 credential or exception body. Failure stages
are fixed labels (`preflight`, `fixture`, `case`, `receipt_changed`, `cleanup`)
and `owned_cleanup_completed` appears only after a successful owned cleanup.

## Explicit non-goals

This design does not add Redis HA/Sentinel/Cluster, remote TLS proxying, Kafka,
multi-host PostgreSQL failover, storage fencing, broad Git routing or default
`serve` changes. It does not alter the exact cache product, A4 commit/replay
semantics or the existing `tests/cross_process_partition.py` /
`tests/cross_process_failover.py` gates. It is an opt-in acceptance script and
its pure helper tests only.
