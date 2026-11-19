#!/usr/bin/env python3
"""Real external A4 Redis wake, partition and PG-fallback acceptance.

This is an opt-in native acceptance entry point, never part of a generic gate.
It owns one random PostgreSQL schema, one disposable Redis process, one
byte-transparent loopback relay, one real ``rootyard serve-blob`` process with
``ROOTYARD_A4_WORKER_MODE=external``, and one distinct ``rootyard worker`` in
``ROOTYARD_WORKER_SCOPE=a4-target-audit``. Repository creation and every push are
real Product HTTP/stock-Git operations.

The case proves, with positive evidence:

* the producer has no embedded A4 consumer when external placement is selected;
* the external worker is the only target-audit claimant;
* a healthy push publishes through the relay and is delivered before the next
  possible periodic poll;
* terminal/ref/object/hold/outbox authority is durable and exactly once;
* a Redis cut leaves the push acknowledged and delivers through the external
  worker's mandatory PostgreSQL ticker;
* healing reconnects the same worker and a later healthy push is wake-delivered
  before the next poll;
* duplicate/invalid hints preserve the durable snapshot;
* no legacy ref-index or Ref-CAS projection work appears; and
* read-only and outside actors are refused without changing authority.

No native result is claimed from source inspection. Run only against an owned
PostgreSQL/Garage/Redis fixture with an exact attested binary and matching source
commit.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time
from types import SimpleNamespace
import urllib.parse
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from backup_recovery_cache import OwnedRestoreRedis, build_binding
from blob_only_service import (
    BlobOnlyHarness,
    NativeProfile,
    ProfileError,
    check_blob_profile,
    git_failure,
    parse_push,
    push_success,
    sha256_file,
    write_report,
)
from cross_process import CrossProcessHarness
from redis_partition_relay import RedisPartitionRelay

CASE = "real_a4_redis_wake_external_pg_fallback"
REPORT_KIND = "rootyard/a4-redis-wake-external-acceptance"
WORKER_NAME = "rootyard_a4_redis_wake_worker"
TARGET_KIND = "pg_refstore_core_commit_audit"
TARGET_CONSUMER = "audit-log"
TARGET_REF = "refs/heads/main"
POLL_SECONDS = 20
LIMITATIONS = [
    "This opt-in case requires an exact attested binary, matching clean source commit, loopback PostgreSQL, owned Redis and an owned Garage/S3 profile; it does not run in the generic gate.",
    "Loopback functional timings are not a scalability benchmark.",
    "A cut relay proves advisory Redis loss and PostgreSQL polling repair; it is not kernel, power-loss, Redis HA or multi-host failover evidence.",
    "The fixture uses the real stock Git CLI over Smart HTTP; SSH and non-loopback HTTP are outside this case.",
    "The owned Redis process and relay are single-host test fixtures; production TLS/ACL deployment is not exercised here.",
]


def need(condition, message):
    if not condition:
        raise ProfileError(message)


class A4RedisWakeHarness(BlobOnlyHarness):
    def __init__(self, args, profile, blob_profile, redis_binary):
        super().__init__(args, profile, blob_profile)
        self.redis_binary = redis_binary
        self.owned_redis = OwnedRestoreRedis(redis_binary)
        self.relay = None
        self.workers = []
        self.worker_count = 0
        self.channel = "rootyard:a4:test:" + self.schema
        self.redis_started = False

    # ---- owned processes -------------------------------------------------
    def stop_workers(self):
        first = None
        for proc, log in list(self.workers):
            try:
                CrossProcessHarness.stop_process(proc)
                if proc.poll() is None:
                    raise RuntimeError("owned A4 worker did not exit after SIGKILL")
            except (Exception, KeyboardInterrupt) as error:
                # Keep the exact owner tuple and open log for diagnosis. Parent
                # cleanup will not touch the schema/scratch until every worker
                # reports a positive exit.
                first = first or error
                continue
            try:
                log.close()
            except (Exception, KeyboardInterrupt) as error:
                first = first or error
                continue
            self.workers.remove((proc, log))
        if first is not None:
            raise first

    def worker_env(self):
        env = self.env.copy()
        db = urllib.parse.urlsplit(env["DATABASE_URL"])
        query = urllib.parse.parse_qsl(db.query, keep_blank_values=True)
        env["DATABASE_URL"] = urllib.parse.urlunsplit(
            db._replace(query=urllib.parse.urlencode(query + [("application_name", WORKER_NAME)]))
        )
        env.update(
            ROOTYARD_WORKER_SCOPE="a4-target-audit",
            ROOTYARD_A4_WAKE_TRANSPORT="redis",
            ROOTYARD_REDIS_URL=f"redis://127.0.0.1:{self.relay.port}/0",
            ROOTYARD_A4_WAKE_CHANNEL=self.channel,
            ROOTYARD_WORKER_POLL_MS=str(POLL_SECONDS * 1000),
            ROOTYARD_WORKER_BATCH="64",
            ROOTYARD_WORKER_LEASE_SECONDS="60",
        )
        env.pop("ROOTYARD_WORKER_CONSUMERS", None)
        env.pop("ROOTYARD_WAKE_TRANSPORT", None)
        env.pop("ROOTYARD_WAKE_CHANNEL", None)
        env.pop("PGAPPNAME", None)
        return env

    def spawn_worker(self):
        env = self.worker_env()
        assert env["ROOTYARD_A4_WAKE_CHANNEL"] == self.env["ROOTYARD_A4_WAKE_CHANNEL"] == self.channel
        assert env["ROOTYARD_REDIS_URL"] == self.env["ROOTYARD_REDIS_URL"]
        self.worker_count += 1
        log_path = self.root / f"a4-worker-{self.worker_count}.log"
        log = open(log_path, "ab")
        try:
            proc = subprocess.Popen(
                [str(self.profile.binary), "worker"],
                env=env,
                stdout=log,
                stderr=log,
                start_new_session=True,
            )
        except BaseException:
            log.close()
            raise
        self.workers.append((proc, log))
        assert Path(f"/proc/{proc.pid}/exe").samefile(self.profile.binary), "A4 worker executable differs"
        return proc

    def stop_redis(self):
        if self.redis_started:
            self.owned_redis.stop()
            self.redis_started = False

    def close_relay(self):
        if self.relay is not None:
            self.relay.close()
            self.relay = None

    def cleanup(self):
        first = None
        # Always attempt the independently owned process/socket stops. The
        # inherited schema/scratch teardown runs only after every worker and the
        # serve-blob process have positively exited and all stops succeeded.
        for action in (self.stop_workers, self.stop, self.close_relay, self.stop_redis):
            try:
                action()
            except (Exception, KeyboardInterrupt) as error:
                first = first or error
        if first is None:
            try:
                super().cleanup()
            except (Exception, KeyboardInterrupt) as error:
                first = error
        if first is not None:
            raise first

    # ---- fixture ---------------------------------------------------------
    def setup_partition(self):
        self.owned_redis.start(self.root)
        self.redis_started = True
        self.relay = RedisPartitionRelay(self.owned_redis.redis_port)
        self.env.update(
            ROOTYARD_A4_WORKER_MODE="external",
            ROOTYARD_A4_WAKE_TRANSPORT="redis",
            ROOTYARD_REDIS_URL=f"redis://127.0.0.1:{self.relay.port}/0",
            ROOTYARD_A4_WAKE_CHANNEL=self.channel,
        )
        # Harness.setup creates the owned schema, accounts and the real
        # serve-blob process. The external mode is already in self.env.
        self.prepare()
        self.sql(
            """CREATE TABLE test_a4_claims (
                n BIGSERIAL PRIMARY KEY, event_id TEXT, consumer TEXT,
                owner UUID, state TEXT, app TEXT,
                recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp());
            CREATE FUNCTION test_a4_claim_trace() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
              IF NEW.consumer = 'audit-log' THEN
                INSERT INTO test_a4_claims(event_id,consumer,owner,state,app)
                VALUES (NEW.event_id,NEW.consumer,NEW.lease_owner,NEW.state,
                        current_setting('application_name', true));
              END IF;
              RETURN NEW;
            END $$;
            CREATE TRIGGER test_a4_claim_trace AFTER INSERT OR UPDATE ON event_deliveries
            FOR EACH ROW EXECUTE FUNCTION test_a4_claim_trace();"""
        )

    # ---- bounded observation helpers ------------------------------------
    def until(self, predicate, description, timeout=20):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            for proc, _ in self.workers:
                assert proc.poll() is None, "A4 worker exited unexpectedly"
            if predicate():
                return
            time.sleep(0.05)
        raise AssertionError("Timed out: " + description)

    def redis_command(self, *parts):
        assert self.redis_started and self.owned_redis.process is not None, "owned Redis is not running"
        return self.owned_redis.redis_command(*parts)

    def publishes(self):
        raw = self.redis_command("INFO", "commandstats")
        assert raw.startswith(b"# Commandstats"), "Redis command counters missing"
        row = re.search(rb"^cmdstat_publish:calls=(\d+),", raw, re.MULTILINE)
        return int(row[1]) if row else 0

    def subscriber_count(self):
        channel, count = self.redis_command("PUBSUB", "NUMSUB", self.channel)
        assert channel == self.channel.encode(), "Redis returned another channel"
        return count

    def worker_idle(self):
        total = int(self.sql(
            f"SELECT count(*) FROM pg_stat_activity WHERE application_name='{WORKER_NAME}'"
        ))
        active = int(self.sql(
            f"SELECT count(*) FROM pg_stat_activity WHERE application_name='{WORKER_NAME}' AND state='active'"
        ))
        return total > 0 and active == 0

    def settle_worker(self):
        self.until(self.worker_idle, "A4 worker idle", 10)
        time.sleep(0.3)
        assert self.worker_idle(), "A4 worker was not idle after its wake scan"

    # ---- durable facts ---------------------------------------------------
    @staticmethod
    def repo_uuid(repo_or_id):
        return str(uuid.UUID(str(repo_or_id)))

    def snapshot(self, repo_id):
        repo = self.repo_uuid(repo_id)
        return {
            "repository": self.sql(
                f"SELECT storage_backend || '|' || storage_generation::text || '|' || object_format "
                f"FROM repositories WHERE id='{repo}'"
            ),
            "refs": self.sql(
                f"SELECT ref_name || '|' || oid FROM ref_store_core_refs "
                f"WHERE repository_id='{repo}' ORDER BY ref_name"
            ),
            "gate_revision": self.sql(f"SELECT revision::text FROM ref_store_core_gates WHERE repository_id='{repo}'"),
            "operations": self.sql(
                f"SELECT count(*)::text || '|' || COALESCE(string_agg(state || ':' || operation_id::text, ',' "
                f"ORDER BY operation_id), '') FROM ref_store_operations WHERE repository_id='{repo}'"
            ),
            "core_events": self.sql(
                f"SELECT count(*)::text || '|' || COALESCE(string_agg(outcome || ':' || operation_id::text, ',' "
                f"ORDER BY operation_id), '') FROM ref_store_core_events WHERE repository_id='{repo}'"
            ),
            "holds": self.sql(f"SELECT count(*) FROM artifact_holds WHERE repository_id='{repo}'"),
            "consume_receipts": self.sql(
                f"SELECT count(*) FROM artifact_hold_consume_receipts WHERE repository_id='{repo}'"
            ),
            "memberships": self.sql(
                f"SELECT count(*) FROM ref_store_core_pack_memberships WHERE repository_id='{repo}'"
            ),
            "outbox": self.sql(f"SELECT count(*) FROM outbox_events WHERE repository_id='{repo}'"),
            "deliveries": self.sql(
                f"SELECT d.consumer || '|' || d.state || '|' || count(*)::text "
                f"FROM event_deliveries d JOIN outbox_events e USING(event_id) "
                f"WHERE e.repository_id='{repo}' GROUP BY d.consumer,d.state ORDER BY 1,2"
            ),
            "audit": self.sql(
                f"SELECT count(*) FROM audit_events a JOIN outbox_events e USING(event_id) "
                f"WHERE e.repository_id='{repo}'"
            ),
            "legacy_projection": self.sql(
                f"SELECT count(*) FROM repository_ref_projection WHERE repository_id='{repo}'"
            ),
            "projection_jobs": self.sql(
                f"SELECT count(*) FROM ref_cas_projection_jobs WHERE repository_id='{repo}'"
            ),
        }

    def claim_rows(self, repo_id):
        repo = self.repo_uuid(repo_id)
        return self.sql(
            f"SELECT c.event_id || '|' || c.consumer || '|' || COALESCE(c.owner::text,'') || '|' || "
            f"c.state || '|' || COALESCE(c.app,'') FROM test_a4_claims c "
            f"JOIN outbox_events e USING(event_id) WHERE e.repository_id='{repo}' ORDER BY c.n"
        )

    def audit_count(self, operation_id):
        op = self.repo_uuid(operation_id)
        return int(self.sql(
            f"SELECT count(*) FROM audit_events a JOIN outbox_events e USING(event_id) "
            f"WHERE e.operation_id='{op}'"
        ))

    def delivery_state(self, operation_id):
        op = self.repo_uuid(operation_id)
        return self.sql(
            f"SELECT d.state || '|' || d.consumer FROM event_deliveries d "
            f"JOIN outbox_events e USING(event_id) WHERE e.operation_id='{op}' ORDER BY d.consumer"
        )

    def assert_claim(self, operation_id):
        op = self.repo_uuid(operation_id)
        delivered = self.sql(
            f"SELECT c.state || '|' || COALESCE(c.app,'') FROM test_a4_claims c "
            f"JOIN outbox_events e USING(event_id) WHERE e.operation_id='{op}' "
            f"AND c.consumer='{TARGET_CONSUMER}' AND c.state='delivered' ORDER BY c.n DESC LIMIT 1"
        )
        assert delivered == f"delivered|{WORKER_NAME}", "external A4 worker did not own the delivered claim"
        foreign = int(self.sql(
            f"SELECT count(*) FROM test_a4_claims c JOIN outbox_events e USING(event_id) "
            f"WHERE e.operation_id='{op}' AND c.consumer='{TARGET_CONSUMER}' "
            f"AND c.state='delivered' AND COALESCE(c.app,'') <> '{WORKER_NAME}'"
        ))
        assert foreign == 0, "an embedded/non-external process delivered the A4 claim"

    def operation_facts(self, repo_id, operation_id):
        repo, op = self.repo_uuid(repo_id), self.repo_uuid(operation_id)
        return self.sql(
            f"""SELECT concat_ws('|',
                (SELECT state FROM ref_store_operations WHERE repository_id='{repo}' AND operation_id='{op}'),
                (SELECT (terminal_result IS NOT NULL)::text FROM ref_store_operations
                   WHERE repository_id='{repo}' AND operation_id='{op}'),
                (SELECT count(*) FROM ref_store_core_events
                   WHERE repository_id='{repo}' AND operation_id='{op}' AND outcome='committed'),
                (SELECT count(*) FROM outbox_events WHERE repository_id='{repo}' AND operation_id='{op}'),
                (SELECT count(*) FROM event_deliveries d JOIN outbox_events e USING(event_id)
                   WHERE e.operation_id='{op}' AND d.consumer='{TARGET_CONSUMER}'),
                (SELECT count(*) FROM event_deliveries d JOIN outbox_events e USING(event_id)
                   WHERE e.operation_id='{op}' AND d.consumer='ref-index'),
                (SELECT count(*) FROM audit_events a JOIN outbox_events e USING(event_id)
                   WHERE e.operation_id='{op}'),
                (SELECT count(*) FROM artifact_holds
                   WHERE repository_id='{repo}' AND operation_id='{op}'),
                (SELECT count(*) FROM artifact_hold_consume_receipts
                   WHERE repository_id='{repo}' AND operation_id='{op}'),
                (SELECT count(*) FROM ref_store_core_pack_memberships WHERE repository_id='{repo}'),
                (SELECT count(*) FROM repository_ref_projection WHERE repository_id='{repo}'),
                (SELECT count(*) FROM ref_cas_projection_jobs WHERE repository_id='{repo}')
            )"""
        )

    def assert_operation(self, repo_id, operation_id, oid, *, delivered):
        repo, op = self.repo_uuid(repo_id), self.repo_uuid(operation_id)
        evidence = self.sql(
            f"""SELECT o.outcome || '|' || COALESCE(o.evidence->>'kind','') || '|' ||
                COALESCE(o.evidence->>'authority','') || '|' || COALESCE(o.evidence->>'delivery','') || '|' ||
                COALESCE(o.evidence->>'source','') || '|' || COALESCE(o.evidence->>'core_operation_id','') || '|' ||
                COALESCE(o.evidence->>'core_revision','') || '|' || COALESCE(o.evidence->>'core_outcome','')
                FROM git_operations o WHERE o.repository_id='{repo}' AND o.id='{op}'"""
        )
        parts = evidence.split("|")
        assert len(parts) == 8, "A4 evidence row is incomplete"
        assert parts == [
            "recorded",
            TARGET_KIND,
            "pg_refstore",
            TARGET_CONSUMER,
            "ref_store_core_events",
            op,
            parts[6],
            "committed",
        ], "A4 evidence identity/authority differs"
        revision = int(parts[6])
        facts = self.operation_facts(repo, op).split("|")
        assert len(facts) == 12, "A4 durable fact projection is incomplete"
        (
            operation_state,
            terminal_present,
            core_events,
            outbox,
            audit_delivery,
            legacy_delivery,
            audit_events,
            holds,
            consume_receipts,
            memberships,
            legacy_projection,
            projection_jobs,
        ) = facts
        assert operation_state == "committed" and terminal_present == "true", "A4 terminal is not durable"
        assert core_events == "1" and outbox == "1", "A4 core/outbox cardinality differs"
        assert audit_delivery == "1" and legacy_delivery == "0", "A4 consumer set differs"
        assert audit_events == ("1" if delivered else "0"), "A4 audit effect count differs"
        assert int(holds) >= 1 and consume_receipts == holds, "A4 holds are not durably consumed once"
        assert int(memberships) >= 1, "A4 pack/object membership is missing"
        assert legacy_projection == "0" and projection_jobs == "0", "A4 created legacy projection work"
        gate_revision = int(self.sql(
            f"SELECT revision FROM ref_store_core_gates WHERE repository_id='{repo}'"
        ))
        assert gate_revision >= revision, "A4 gate revision did not cover the committed operation"
        ref_oid = self.sql(
            f"SELECT oid FROM ref_store_core_refs WHERE repository_id='{repo}' AND ref_name='{TARGET_REF}'"
        )
        assert ref_oid == oid, "A4 core ref does not name the acknowledged OID"

    def push_oid(self, work, message):
        self.commit_files(work, message, {"value": message + "\n"})
        oid = self.git("rev-parse", "HEAD", cwd=work).stdout.decode().strip()
        assert re.fullmatch(r"[0-9a-f]{40}", oid), "Git produced a non-SHA1 commit"
        return oid

    def push_with_operation(self, work, branch, token, operation):
        result = self.git(
            "-c",
            "http.extraHeader=X-Rootyard-Operation: " + operation,
            "push",
            "--porcelain",
            "origin",
            f"HEAD:refs/heads/{branch}",
            cwd=work,
            token=token,
            check=False,
        )
        return result

    def commit_and_push(self, work, message):
        oid = self.push_oid(work, message)
        operation = str(uuid.uuid4())
        result = self.push_with_operation(work, "main", self.alice, operation)
        assert result.returncode == 0, "stock Git push failed: " + json.dumps(git_failure(result))
        assert push_success(parse_push(result.stdout.decode()), TARGET_REF), "stock Git did not report push success"
        return oid, operation, result

    # ---- named phases ----------------------------------------------------
    def assert_no_embedded_delivery(self, repo, operation, oid):
        time.sleep(3)
        assert self.audit_count(operation) == 0, "external placement still had an embedded A4 consumer"
        assert self.delivery_state(operation) == f"pending|{TARGET_CONSUMER}", "A4 delivery was not left pending"
        self.assert_operation(repo["id"], operation, oid, delivered=False)

    def start_external_worker(self, repo, operation, oid):
        start = time.monotonic()
        self.spawn_worker()
        self.until(
            lambda: self.subscriber_count() == 1 and self.relay.counts().active >= 1,
            "external A4 worker subscribed through relay",
            10,
        )
        self.until(lambda: self.audit_count(operation) == 1, "external worker initial catch-up delivery", 10)
        self.assert_claim(operation)
        self.assert_operation(repo["id"], operation, oid, delivered=True)
        self.settle_worker()
        return start

    def healthy_push(self, work, repo, deadline):
        self.settle_worker()
        published = self.publishes()
        relay_before = self.relay.counts()
        oid, operation, _ = self.commit_and_push(work, "healthy-" + uuid.uuid4().hex)
        self.until(lambda: self.publishes() > published, "A4 producer published through relay", 5)
        self.until(lambda: self.audit_count(operation) == 1, "external A4 worker healthy delivery", 8)
        assert time.monotonic() < deadline, "A4 healthy delivery overlapped the next possible periodic poll"
        after = self.relay.counts()
        assert after.forwarded > relay_before.forwarded, "healthy delivery did not use the relay"
        assert self.subscriber_count() == 1, "external A4 subscriber disappeared during healthy delivery"
        self.assert_claim(operation)
        self.assert_operation(repo["id"], operation, oid, delivered=True)
        return oid, operation

    def duplicate_and_invalid_hints(self, repo):
        self.settle_worker()
        before = self.snapshot(repo["id"])
        claims = self.claim_rows(repo["id"])
        for _ in range(10):
            self.redis_command("PUBLISH", self.channel, b"v1")
        self.redis_command("PUBLISH", self.channel, b"wrong-version")
        self.redis_command("PUBLISH", "rootyard:a4:test:other", b"v1")
        time.sleep(0.5)
        self.until(lambda: self.subscriber_count() == 1, "subscriber recovered from invalid hints", 10)
        self.settle_worker()
        assert self.snapshot(repo["id"]) == before, "duplicate/invalid hints changed durable authority"
        assert self.claim_rows(repo["id"]) == claims, "duplicate/invalid hints created a new claim"

    def cut_fallback_push(self, work, repo, first_poll):
        self.settle_worker()
        published = self.publishes()
        relay_before = self.relay.counts()
        assert relay_before.active >= 1 and self.subscriber_count() == 1, "no established external subscriber to cut"
        assert self.relay.cut() >= 1, "relay cut reaped no established connection"
        self.until(
            lambda: self.subscriber_count() == 0 and self.relay.counts().refused > relay_before.refused,
            "cut subscriber and refused reconnect",
            10,
        )
        oid, operation, _ = self.commit_and_push(work, "cut-" + uuid.uuid4().hex)
        assert self.git("ls-remote", "--refs", self.base + repo["clone_path"], TARGET_REF,
                        token=self.alice).returncode == 0
        remaining = first_poll - 1 - time.monotonic()
        if remaining > 0:
            time.sleep(remaining)
        assert time.monotonic() < first_poll, "fixture missed the pre-poll observation window"
        assert self.audit_count(operation) == 0, "cut delivery occurred before the PostgreSQL poll"
        assert self.publishes() == published, "cut publish reached the owned Redis"
        self.until(
            lambda: self.audit_count(operation) == 1,
            "external worker PostgreSQL poll delivered after cut",
            max(1.0, first_poll - time.monotonic()) + 10,
        )
        assert time.monotonic() >= first_poll, "pre-poll delivery was mislabeled as fallback"
        assert self.publishes() == published, "fallback delivery was accompanied by a Redis publish"
        assert self.relay.counts().forwarded == relay_before.forwarded, "cut relay forwarded a hint"
        self.assert_claim(operation)
        self.assert_operation(repo["id"], operation, oid, delivered=True)
        return oid, operation

    def healed_push(self, work, repo, second_poll):
        self.relay.heal()
        self.until(
            lambda: self.subscriber_count() == 1 and self.relay.counts().active >= 1,
            "external worker resubscribed after heal",
            10,
        )
        self.settle_worker()
        assert time.monotonic() < second_poll - 1, "heal/resubscribe ran past the next poll window"
        return self.healthy_push(work, repo, second_poll)

    def assert_denials(self, repo, work, oid):
        before = self.snapshot(repo["id"])
        remote = self.base + repo["clone_path"]
        denied_reader = self.git(
            "push", "--porcelain", "origin", "HEAD:refs/heads/readonly-denied",
            cwd=work, token=self.reader, check=False,
        )
        assert denied_reader.returncode != 0 and not push_success(
            parse_push(denied_reader.stdout.decode()), "refs/heads/readonly-denied"
        ), "read-only token was not refused"
        denied_outside = self.git(
            "push", "--porcelain", "origin", "HEAD:refs/heads/outside-denied",
            cwd=work, token=self.bob, check=False,
        )
        assert denied_outside.returncode != 0 and not push_success(
            parse_push(denied_outside.stdout.decode()), "refs/heads/outside-denied"
        ), "outside actor was not refused"
        assert self.snapshot(repo["id"]) == before, "denied pushes changed durable authority"
        refs = self.remote_refs(remote, self.alice)
        assert refs.get(TARGET_REF) == oid, "authorized ref changed after denials"
        assert not any(name.endswith(("readonly-denied", "outside-denied")) for name in refs)
        clone = self.root / "a4-reader-clone"
        self.clone(remote, clone, self.reader)
        assert self.git("rev-parse", "HEAD", cwd=clone).stdout.decode().strip() == oid
        self.git("fsck", "--full", "--strict", cwd=clone)

    def run_case(self):
        repo, _ = self.create("a4wake", self.alice)
        remote = self.base + repo["clone_path"]
        work = self.root / "a4wake-work"
        self.empty_clone(remote, work, self.alice)
        self.configure(work)
        initial_oid, initial_op, _ = self.commit_and_push(work, "initial")
        self.assert_ref(remote, TARGET_REF, initial_oid)
        self.assert_no_embedded_delivery(repo, initial_op, initial_oid)
        start = self.start_external_worker(repo, initial_op, initial_oid)
        first_poll = start + POLL_SECONDS
        healthy_oid, healthy_op = self.healthy_push(work, repo, first_poll)
        self.assert_ref(remote, TARGET_REF, healthy_oid)
        self.duplicate_and_invalid_hints(repo)
        cut_oid, cut_op = self.cut_fallback_push(work, repo, first_poll)
        self.assert_ref(remote, TARGET_REF, cut_oid)
        second_poll = start + 2 * POLL_SECONDS
        healed_oid, healed_op = self.healed_push(work, repo, second_poll)
        self.assert_ref(remote, TARGET_REF, healed_oid)
        self.assert_denials(repo, work, healed_oid)
        final = self.snapshot(repo["id"])
        assert final["legacy_projection"] == "0", "legacy ref projection exists"
        assert final["projection_jobs"] == "0", "legacy Ref-CAS projection job exists"
        return dict(
            external_worker_mode_serving=True,
            no_embedded_consumer_before_external_start=True,
            external_worker_only_claim=True,
            healthy_publish_forwarded=True,
            healthy_delivery_before_periodic_poll=True,
            durable_terminal_ref_object_hold_outbox=True,
            redis_cut_push_acknowledged=True,
            redis_cut_delivery_by_postgres_poll=True,
            redis_cut_no_publish_forwarded=True,
            healed_resubscribe_and_wake_before_poll=True,
            duplicate_and_invalid_hints_preserved_snapshot=True,
            no_legacy_ref_index_or_projection=True,
            read_only_denied=True,
            outside_actor_denied=True,
            authorized_read_after_denials=True,
            initial_operation=initial_op,
            healthy_operation=healthy_op,
            cut_operation=cut_op,
            healed_operation=healed_op,
            poll_seconds=POLL_SECONDS,
            owned_cleanup_completed=True,
        )


def preflight(args):
    env = os.environ.copy()
    need(__debug__, "A4 acceptance requires assertions")
    need(sys.platform.startswith("linux"), "the real serve-blob/A4 worker acceptance requires Linux procfs")
    need(not env.get("ROOTYARD_TEST_EVIDENCE_DIR"), "evidence-directory substitution is not accepted")
    need(env.get("ROOTYARD_TEST_DATABASE_URL"), "ROOTYARD_TEST_DATABASE_URL is required")
    database = urllib.parse.urlsplit(env["ROOTYARD_TEST_DATABASE_URL"])
    need(database.scheme in ("postgresql", "postgres"), "test database must be PostgreSQL")
    need(database.hostname in ("127.0.0.1", "::1", "localhost"), "test database must be loopback")
    need(not database.query, "test database URL must not carry a query")
    need(shutil.which("psql"), "psql is required")
    redis_binary = CrossProcessHarness.resolve_redis()
    need(redis_binary, "ROOTYARD_TEST_REDIS_SERVER or redis-server is required; Redis coverage is mandatory")
    binding = build_binding(args.binary, args.expect_commit)
    profile = NativeProfile(args.binary, args.git, env)
    blob_profile = check_blob_profile(env)
    return SimpleNamespace(
        binding=binding,
        redis_binary=redis_binary,
        profile=profile,
        blob_profile=blob_profile,
        harness_sha256=sha256_file(Path(__file__)),
    )


def result_report(binding, case, passed, harness_sha256=None):
    report = dict(
        kind=REPORT_KIND,
        qualification_kind="clean-candidate" if binding.get("source_head") else "unbound",
        measurement_kind="native_execution",
        simulated_fields=False,
        passed=bool(passed),
        expected_cases=[CASE],
        case_count=len([case]),
        expected_count=1,
        skips=0,
        pending_cases=[],
        cases=[case],
        limitations=LIMITATIONS,
        **binding,
    )
    if harness_sha256:
        report["harness_sha256"] = harness_sha256
    return report


def acceptance_report(args, *, harness_type=None, preflight_fn=None):
    prepare = preflight_fn or preflight
    binding = {}
    harness = None
    harness_sha256 = None
    primary = "preflight"
    cleanup_error = None
    detail = None
    try:
        prepared = prepare(args)
        binding = prepared.binding
        harness_sha256 = prepared.harness_sha256
        primary = "fixture"
        harness = (harness_type or A4RedisWakeHarness)(
            args, prepared.profile, prepared.blob_profile, prepared.redis_binary
        )
        harness.setup_partition()
        primary = "case"
        detail = harness.run_case()
        primary = "receipt_changed"
        assert build_binding(args.binary, args.expect_commit) == binding, "source/receipt binding changed"
        assert sha256_file(Path(__file__)) == harness_sha256, "acceptance harness changed"
        primary = None
    except (Exception, KeyboardInterrupt):
        pass
    finally:
        if harness is not None:
            try:
                harness.cleanup()
            except (Exception, KeyboardInterrupt):
                cleanup_error = "cleanup"
    passed = primary is None and cleanup_error is None
    if passed:
        case = dict(name=CASE, status="passed", detail=dict(detail, owned_cleanup_completed=True))
    else:
        case = dict(name=CASE, status="failed", error=primary or cleanup_error)
        if primary is not None and cleanup_error is not None:
            case["cleanup_error"] = cleanup_error
    return result_report(binding, case, passed, harness_sha256)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True, help="absolute attested rootyard binary")
    parser.add_argument("--git", help="absolute trusted Git (defaults to ROOTYARD_GIT)")
    parser.add_argument("--expect-commit", required=True, help="exact clean source commit bound to the binary")
    parser.add_argument("--report", type=Path, required=True, help="exact JSON report destination")
    parser.add_argument("--keep", action="store_true", help="keep owned temporary files; the random schema is still dropped")
    args = parser.parse_args(argv)
    args.binary = str(args.binary.resolve())

    def interrupted(_signum, _frame):
        raise KeyboardInterrupt

    previous = signal.signal(signal.SIGTERM, interrupted)
    try:
        report = acceptance_report(args)
        try:
            write_report(args.report, report)
        except OSError:
            report = result_report(
                {key: value for key, value in report.items() if key in (
                    "source_head", "source_tree", "source_inputs_sha256",
                    "binary_sha256", "build_receipt_sha256",
                )},
                dict(name=CASE, status="failed", error="report_write"),
                False,
                report.get("harness_sha256"),
            )
    finally:
        signal.signal(signal.SIGTERM, previous)
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
