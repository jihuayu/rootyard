#!/usr/bin/env python3
"""Opt-in manual Redis promotion behind a job-owned loopback advisory endpoint.

Browse uses Memory. Cache survival and managed or Sentinel topologies require
separate fixtures.
"""
from contextlib import ExitStack
import time

from backup_recovery_cache import OwnedRestoreRedis
from cross_process_partition import RedisPartitionHarness, main, partition_report


CASE = "real_redis_advisory_replica_promotion_and_duplicate_wakes"
CANARY_KEY = "rootyard-test:replication-canary"
CANARY = b"owned-replica"
SNAPSHOT_TABLES = (
    "git_operations", "outbox_events", "event_deliveries", "audit_events",
    "repository_ref_projection", "test_delivery_trace",
)


def replication_status(redis, command=None):
    if command is None:
        command = redis.redis_command
    assert redis._identity_on(command) == redis.run_id, "Owned Redis identity changed"
    raw = command("INFO", "replication")
    assert raw.startswith(b"# Replication")
    return dict(line.split(b":", 1) for line in raw.splitlines() if b":" in line)


class RedisFailoverHarness(RedisPartitionHarness):
    def __init__(self, args, redis_binary):
        super().__init__(args, redis_binary)
        self.primary = self.owned_redis
        self.replica = OwnedRestoreRedis(redis_binary)

    def replica_link(self, state, command=None):
        status = replication_status(self.replica, command)
        assert status[b"role"] == b"slave"
        assert status[b"master_host"] == b"127.0.0.1"
        assert int(status[b"master_port"]) == self.primary.redis_port
        return status[b"master_link_status"] == state and status[b"master_sync_in_progress"] == b"0"

    def assert_canary(self):
        assert self.replica.redis_command("STRLEN", CANARY_KEY) == len(CANARY)
        assert self.replica.redis_command("GET", CANARY_KEY) == CANARY

    def setup_partition(self):
        super().setup_partition()
        replica_root = self.root / "replica"
        replica_root.mkdir()
        self.replica.start(replica_root)
        assert self.primary.redis_port != self.replica.redis_port
        assert self.primary.process.pid != self.replica.process.pid
        assert self.primary.run_id != self.replica.run_id
        assert replication_status(self.primary)[b"role"] == b"master"

        def unattached(command):
            assert replication_status(self.replica, command)[b"role"] == b"master"

        assert self.replica.redis_command("REPLICAOF", "127.0.0.1", self.primary.redis_port,
                                          before_send=unattached) == b"OK"
        self.until(lambda: self.replica_link(b"up"), "owned replica linked", timeout=15)
        assert replication_status(self.primary)[b"connected_slaves"] == b"1"
        assert self.replica.redis_command("STRLEN", CANARY_KEY) == 0

        def primary_role(command):
            assert replication_status(self.primary, command)[b"role"] == b"master"

        assert self.primary.redis_command("SET", CANARY_KEY, CANARY, before_send=primary_role) == b"OK"
        self.until(lambda: self.replica.redis_command("STRLEN", CANARY_KEY) == len(CANARY),
                   "replica received primary canary", timeout=5)
        self.assert_canary()

    def prepare_outage(self, published):
        super().prepare_outage(published)
        assert self.publishes() == published and self.replica_link(b"up")
        self.assert_canary()
        assert replication_status(self.primary)[b"role"] == b"master"
        self.primary.stop()
        assert self.primary.process.poll() is not None
        self.until(lambda: self.replica_link(b"down"), "replica observed stopped primary", timeout=5)
        self.owned_redis = self.replica
        self.assert_redis_alive()
        return self.publishes()

    def heal_endpoint(self):
        assert self.primary.process.poll() is not None

        def attached_to_stopped_primary(command):
            assert self.replica_link(b"down", command)

        assert self.replica.redis_command("REPLICAOF", "NO", "ONE",
                                          before_send=attached_to_stopped_primary) == b"OK"
        self.until(lambda: replication_status(self.replica)[b"role"] == b"master",
                   "owned replica became primary", timeout=5)
        self.assert_canary()
        self.relay.heal(redis_port=self.replica.redis_port)

    def durable_snapshot(self):
        refs = self.git("ls-remote", self.remote, token=self.reader).stdout
        rows = tuple(
            self.sql(f"SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)), '[]'::jsonb) FROM {table} t")
            for table in SNAPSHOT_TABLES
        )
        return refs, rows

    def assert_duplicate_wakes(self, oid, settled_scans, deadline):
        self.until(lambda: self.scans() == settled_scans, "post-push follow-up scan finished", timeout=5)
        before = self.durable_snapshot()
        published = self.publishes()
        assert time.monotonic() < deadline
        for scan in range(settled_scans + 1, settled_scans + 4):
            assert self.redis_command("PUBLISH", self.channel, b"v1") == 1
            self.until(lambda: self.scans() == scan, "duplicate hint reached the worker", timeout=5)
        assert time.monotonic() < deadline
        assert self.publishes() == published + 3
        assert self.durable_snapshot() == before
        self.assert_effects(oid, 3)

    def partition(self):
        healed, settled_scans, deadline = self.exercise_wake_cut()
        self.assert_duplicate_wakes(healed, settled_scans, deadline)
        assert self.primary.process.poll() is not None
        assert replication_status(self.replica)[b"role"] == b"master"
        return dict(
            owned_replication_link_and_canary_verified=True, old_owned_primary_stopped=True,
            outage_push_delivered_once_by_pg_poll=True, outage_clone_and_fsck_exact=True,
            replica_promoted_and_worker_resubscribed_at_same_endpoint=True,
            post_promotion_push_woke_worker_before_poll=True,
            duplicate_v1_wakes_preserved_git_and_pg_state=True,
        )

    def stop_redis_fixtures(self):
        with ExitStack() as cleanup:
            cleanup.callback(self.primary.stop)
            self.replica.stop()


def failover_report(args):
    return partition_report(args, harness_type=RedisFailoverHarness, case_name=CASE, fault_stage="promotion")


if __name__ == "__main__":
    raise SystemExit(main(failover_report, case_name=CASE, description=__doc__))
