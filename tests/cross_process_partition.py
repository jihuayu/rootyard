#!/usr/bin/env python3
"""Opt-in Redis wake partition with an exact state-redis CLI receipt and owned PG schema."""
import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import re
import shutil
import signal
import time
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
import uuid

from backup_recovery_cache import OwnedRestoreRedis, build_binding
from cross_process import CrossProcessHarness
from redis_partition_relay import RedisPartitionRelay


CASE = "real_redis_partition_pg_fallback_and_wake"
POLL_SECONDS = 20
WORKER_NAME = "rootyard_redis_partition_worker"
REF = "refs/heads/branch-0"


class RedisPartitionHarness(CrossProcessHarness):
    def __init__(self, args, redis_binary):
        super().__init__(args)
        self.owned_redis = OwnedRestoreRedis(redis_binary)
        self.relay = None
        self.env["ROOTYARD_CACHE_BACKEND"] = "memory"
        self.env.pop("ROOTYARD_REDIS_ADDRESS", None)

    def worker_env(self, **kwargs):
        env = super().worker_env(**kwargs)
        db = urlsplit(env["DATABASE_URL"])
        env["DATABASE_URL"] = urlunsplit(db._replace(
            query=urlencode(parse_qsl(db.query) + [("application_name", WORKER_NAME)]),
        ))
        return env

    def setup_partition(self):
        self.owned_redis.start(self.root)
        self.relay = RedisPartitionRelay(self.owned_redis.redis_port)
        self.redis_port = self.relay.port
        self.env.update(
            ROOTYARD_WAKE_TRANSPORT="redis",
            ROOTYARD_REDIS_URL=f"redis://127.0.0.1:{self.redis_port}/0",
            ROOTYARD_WAKE_CHANNEL=self.channel,
        )
        self.fixture()
        assert Path(f"/proc/{self.proc.pid}/exe").samefile(self.args.binary)
        assert self.sql("SELECT count(*) FROM ref_cas_projection_jobs") == "0"
        # The empty projector claim runs after both outbox consumers finish a scan.
        self.sql(f"""CREATE TABLE test_partition_scans (seen boolean DEFAULT true);
            CREATE FUNCTION test_partition_scan() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
              IF current_setting('application_name') = '{WORKER_NAME}' THEN
                INSERT INTO test_partition_scans DEFAULT VALUES;
              END IF;
              RETURN NULL;
            END $$;
            CREATE TRIGGER test_partition_scan AFTER UPDATE OF last_error ON ref_cas_projection_jobs
            FOR EACH STATEMENT EXECUTE FUNCTION test_partition_scan();""")

    def scans(self):
        return int(self.sql("SELECT count(*) FROM test_partition_scans"))

    def subscriber_count(self):
        channel, count = self.owned_redis.redis_command("PUBSUB", "NUMSUB", self.channel)
        assert channel == self.channel.encode()
        return count

    def assert_redis_alive(self):
        assert self.owned_redis.identity() == self.owned_redis.run_id
        self.owned_redis.counts()

    def publishes(self):
        raw = self.owned_redis.redis_command("INFO", "commandstats")
        assert raw.startswith(b"# Commandstats")
        row = re.search(rb"^cmdstat_publish:calls=(\d+),", raw, re.MULTILINE)
        return int(row[1]) if row else 0

    def push_oid(self):
        self.push()
        oid = self.git("rev-parse", "HEAD", cwd=self.work).stdout.decode().strip()
        assert re.fullmatch(r"[0-9a-f]{40}", oid)
        return oid

    def assert_effects(self, oid, events):
        assert self.invariants()["events"] == events
        repo = str(uuid.UUID(self.repo["id"]))
        assert self.sql(f"""SELECT count(*) FROM repository_ref_projection p
          JOIN outbox_events e ON (e.event_id,e.repository_id,e.ref_name)=(p.event_id,p.repository_id,p.ref_name)
          JOIN git_operations o ON o.id=e.operation_id
          JOIN audit_events a ON a.event_id=e.event_id
          WHERE p.repository_id='{repo}' AND p.ref_name='{REF}'
            AND p.oid='{oid}' AND e.new_oid='{oid}' AND o.outcome='recorded'
            AND (SELECT count(*) FROM test_delivery_trace t
                 WHERE t.event_id=e.event_id AND t.state='delivered'
                   AND t.consumer IN ('audit-log','ref-index'))=2""") == "1"
        advertised = self.git("ls-remote", "--refs", self.remote, REF, token=self.reader).stdout
        assert advertised == f"{oid}\t{REF}\n".encode()

    def healthy_push(self, deadline):
        published, relay_before = self.publishes(), self.relay.counts()
        oid = self.push_oid()
        self.until(lambda: self.publishes() > published, "producer published through relay", timeout=5)
        self.drain(timeout=5)
        assert time.monotonic() < deadline, "Delivery overlapped the next possible periodic poll"
        assert self.relay.counts().forwarded > relay_before.forwarded and self.subscriber_count() == 1
        return oid

    def partition(self):
        start = time.monotonic()
        worker = self.spawn_worker(poll=POLL_SECONDS * 1000, transport="redis")
        server = self.proc
        assert Path(f"/proc/{worker.pid}/exe").samefile(self.args.binary)
        # The first periodic tick is immediate; subsequent ticks cannot precede these bounds.
        first_poll, second_poll = start + POLL_SECONDS, start + 2 * POLL_SECONDS
        self.until(lambda: self.subscriber_count() == self.relay.counts().active == 1,
                   "worker subscribed through relay", timeout=10)
        self.until(lambda: self.scans() == 2, "initial and subscription scans finished", timeout=5)
        healthy = self.healthy_push(first_poll)
        healthy_scans = 4
        self.until(lambda: self.scans() == healthy_scans, "healthy wake and follow-up scan finished", timeout=5)
        self.assert_effects(healthy, 1)

        published, relay_before = self.publishes(), self.relay.counts()
        assert self.relay.cut() >= 1
        self.until(lambda: self.subscriber_count() == 0 and self.relay.counts().refused > relay_before.refused,
                   "established subscriber cut and reconnect refused", timeout=5)
        self.assert_redis_alive()
        cut = self.push_oid()
        time.sleep(max(0, first_poll - 1 - time.monotonic()))
        assert self.pending() == 2 and self.scans() == healthy_scans and time.monotonic() < first_poll
        self.drain(timeout=10)
        partitioned_scans = healthy_scans + 2
        self.until(lambda: self.scans() == partitioned_scans, "periodic poll and follow-up scan finished", timeout=5)
        assert time.monotonic() >= first_poll and self.subscriber_count() == 0
        assert self.publishes() == published and self.relay.counts().forwarded == relay_before.forwarded
        self.assert_redis_alive()
        self.assert_effects(cut, 2)
        clone = self.root / "partition-clone"
        self.git("clone", "--branch", "branch-0", self.remote, str(clone), token=self.reader)
        assert self.git("rev-parse", "HEAD", cwd=clone).stdout.decode().strip() == cut
        assert (clone / "value").read_bytes() == (self.work / "value").read_bytes()
        self.git("fsck", "--full", "--strict", cwd=clone)

        assert self.relay.port == self.redis_port
        self.relay.heal()
        self.until(lambda: self.subscriber_count() == self.relay.counts().active == 1,
                   "existing worker resubscribed at the same endpoint", timeout=5)
        self.until(lambda: self.scans() == partitioned_scans + 1, "reconnect catch-up scan finished", timeout=5)
        assert time.monotonic() < second_poll
        healed = self.healthy_push(second_poll)
        self.assert_effects(healed, 3)
        self.assert_redis_alive()
        assert self.proc is server and server.poll() is None and worker.poll() is None
        return dict(
            producer_and_worker_used_relay=True, established_and_new_connections_cut=True,
            redis_process_survived_without_flush=True, acknowledged_push_delivered_once_by_pg_poll=True,
            cut_git_ref_clone_and_fsck_exact=True, worker_resubscribed_after_heal=True,
            post_heal_wake_before_next_poll=True,
        )

    def cleanup(self):
        with ExitStack() as cleanup:
            cleanup.callback(shutil.rmtree, self.root)
            if self.schema_created:
                cleanup.callback(self.sql, f'DROP SCHEMA "{self.schema}" CASCADE', isolated=False)
            cleanup.callback(self.owned_redis.stop)
            if self.relay is not None:
                cleanup.callback(self.relay.close)
            cleanup.callback(self.stop)
            self.stop_workers()


def partition_report(args):
    binding = {}
    harness = None
    stage = "preflight"
    try:
        if not __debug__ or os.environ.get("ROOTYARD_TEST_EVIDENCE_DIR"):
            raise RuntimeError("Partition proof requires assertions and disposable evidence")
        db = urlsplit(os.environ["ROOTYARD_TEST_DATABASE_URL"])
        assert db.scheme in ("postgresql", "postgres") and db.hostname in ("127.0.0.1", "::1") and not db.query
        binding = build_binding(args.binary, args.expect_commit)
        redis_binary = CrossProcessHarness.resolve_redis()
        assert redis_binary
        stage = "fixture"
        harness = RedisPartitionHarness(args, redis_binary)
        harness.setup_partition()
        stage = "partition"
        detail = harness.partition()
        stage = "receipt_changed"
        assert build_binding(args.binary, args.expect_commit) == binding
        stage = None
    except (Exception, KeyboardInterrupt):
        pass
    finally:
        if harness is not None:
            try:
                harness.cleanup()
            except (Exception, KeyboardInterrupt):
                stage = "cleanup"
    case = dict(name=CASE, status="failed", error=stage) if stage else dict(
        name=CASE, status="passed", detail=dict(detail, owned_cleanup_completed=True),
    )
    return dict(passed=stage is None, cases=[case], **binding)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--expect-commit", required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    args.binary = str(args.binary.resolve())

    def interrupted(_signum, _frame):
        raise KeyboardInterrupt

    previous = signal.signal(signal.SIGTERM, interrupted)
    try:
        report = partition_report(args)
        try:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            with args.report.open("x") as output:
                json.dump(report, output, indent=2)
                output.write("\n")
        except OSError:
            report = dict(passed=False, cases=[dict(name=CASE, status="failed", error="report_write")])
    finally:
        signal.signal(signal.SIGTERM, previous)
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
