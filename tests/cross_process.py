#!/usr/bin/env python3
"""Real multi-process PostgreSQL outbox and optional loopback Redis tests.

Owns one disposable SQL schema, Git storage directory and Redis process. Never
connects to an existing Redis server. Set ROOTYARD_TEST_DATABASE_URL; optionally
set ROOTYARD_TEST_REDIS_SERVER to an executable redis-server. No Kafka coverage.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.parse

from e2e import Harness


class CrossProcessHarness(Harness):
    def __init__(self, args):
        super().__init__(args)
        self.env.update(ROOTYARD_OUTBOX_WORKER="false", ROOTYARD_WAKE_TRANSPORT="poll")
        password = urllib.parse.urlsplit(self.base_db).password
        if password:
            self.secrets.extend([password, urllib.parse.unquote(password)])
        self.workers = []
        self.redis = None
        self.redis_log = None
        self.runtime = {}
        self.serial = 0
        self.channel = "rootyard:test:" + self.schema
        self.limits = [
            "Exactly-once assertions cover transactional PostgreSQL effects, not external systems.",
            "SIGKILL tests kill actual worker/Redis processes; no kernel, power-loss or PostgreSQL crash is simulated.",
            "A test-only SQL trigger pauses an actual leased worker to make the kill window deterministic.",
            "Loopback Redis Pub/Sub is advisory; no Redis durability or real Kafka implementation is claimed.",
            "Timings are bounded functional checks, not scalability or production latency benchmarks.",
        ]

    def until(self, predicate, description, timeout=20):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            for proc, _ in self.workers:
                assert proc.poll() is None, "Worker exited unexpectedly (see retained worker logs)"
            if predicate():
                return
            time.sleep(.05)
        raise AssertionError("Timed out: " + description)

    def worker_env(self, consumers="audit-log,ref-index", poll=100, transport="poll"):
        env = self.env.copy()
        no_git = self.root / "empty-path"
        no_git.mkdir(exist_ok=True)
        invalid_dir = self.root / "not-a-directory"
        invalid_dir.touch(exist_ok=True)
        env.update(ROOTYARD_GIT=str(self.root / "missing-git"),
                   ROOTYARD_DATA_DIR=str(invalid_dir / "impossible"), PATH=str(no_git),
                   ROOTYARD_WORKER_CONSUMERS=consumers, ROOTYARD_WORKER_POLL_MS=str(poll),
                   ROOTYARD_WORKER_BATCH="4", ROOTYARD_WORKER_LEASE_SECONDS="2",
                   ROOTYARD_WAKE_TRANSPORT=transport)
        if transport == "redis":
            env.update(ROOTYARD_REDIS_ADDRESS="127.0.0.1:" + str(self.redis_port),
                       ROOTYARD_WAKE_CHANNEL=self.channel)
        return env

    def spawn_worker(self, **kwargs):
        self.serial += 1
        log = open(self.root / ("worker-%d.log" % self.serial), "ab")
        proc = subprocess.Popen([self.args.binary, "worker"], env=self.worker_env(**kwargs),
                                stdout=log, stderr=log, start_new_session=True)
        self.workers.append((proc, log))
        return proc

    def kill_worker(self, proc, hard=False):
        item = next(item for item in self.workers if item[0] is proc)
        self.workers.remove(item)
        self.stop_process(proc, hard)
        item[1].close()

    @staticmethod
    def stop_process(proc, hard=False):
        if proc and proc.poll() is None:
            os.killpg(proc.pid, signal.SIGKILL if hard else signal.SIGTERM)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait(timeout=5)

    def stop_workers(self):
        for proc, _ in list(self.workers):
            self.kill_worker(proc)

    def fixture(self):
        self.setup()
        self.repo = json.loads(self.expect("/api/repos", 201, method="POST", token=self.alice,
                                           body={"name": "cross-process"}))
        self.remote = self.base + self.repo["clone_path"]
        self.work = self.root / "work"
        self.git("clone", self.remote, str(self.work), token=self.alice)
        self.git("config", "user.name", "Cross process test", cwd=self.work)
        self.git("config", "user.email", "test@example.invalid", cwd=self.work)
        # Record actual successful effects and lease owners, without changing the
        # production schema/consumer logic. The sequence also observes ref order.
        self.sql("""CREATE TABLE test_delivery_trace (
            n BIGSERIAL PRIMARY KEY, event_id TEXT, consumer TEXT, owner UUID, state TEXT);
            CREATE FUNCTION test_delivery_trace_fn() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
              IF NEW.state='leased' OR (NEW.state='delivered' AND OLD.state<>'delivered') THEN
                INSERT INTO test_delivery_trace(event_id,consumer,owner,state)
                VALUES(NEW.event_id,NEW.consumer,NEW.lease_owner,NEW.state);
              END IF;
              RETURN NEW;
            END $$;
            CREATE TRIGGER test_delivery_trace AFTER UPDATE ON event_deliveries
            FOR EACH ROW EXECUTE FUNCTION test_delivery_trace_fn();""")
        return {"embedded_worker_disabled": True, "isolated_schema": True}

    def push(self, count=1, branches=1):
        for _ in range(count):
            self.serial += 1
            (self.work / "value").write_text(str(self.serial) + "\n")
            self.git("add", "value", cwd=self.work)
            self.git("commit", "-m", "cross-process-%d" % self.serial, cwd=self.work)
            self.git("push", "origin", *["HEAD:branch-%d" % n for n in range(branches)],
                     cwd=self.work, token=self.alice)

    def pending(self, consumer=None):
        where = "state<>'delivered'"
        if consumer:
            assert consumer in ("audit-log", "ref-index")
            where += " AND consumer='" + consumer + "'"
        return int(self.sql("SELECT count(*) FROM event_deliveries WHERE " + where))

    def drain(self, consumer=None, timeout=20):
        self.until(lambda: self.pending(consumer) == 0, "durable deliveries drained", timeout)

    def invariants(self):
        events = int(self.sql("SELECT count(*) FROM outbox_events"))
        assert int(self.sql("SELECT count(*) FROM audit_events")) == events
        assert int(self.sql("SELECT count(*) FROM event_deliveries WHERE state='delivered'")) == events * 2
        assert self.sql("""SELECT count(*) FROM (
          SELECT event_id,consumer FROM test_delivery_trace WHERE state='delivered'
          GROUP BY event_id,consumer HAVING count(*)<>1) t""") == "0"
        assert self.sql("""SELECT count(*) FROM (
          SELECT e.storage_generation,e.operation_sequence,e.transaction_sequence,
            lag(ROW(e.storage_generation,e.operation_sequence,e.transaction_sequence)) OVER
            (PARTITION BY e.repository_id,e.ref_name,t.consumer ORDER BY t.n) AS prior
          FROM test_delivery_trace t JOIN outbox_events e USING(event_id)
          WHERE t.state='delivered') s
          WHERE prior > ROW(storage_generation,operation_sequence,transaction_sequence)""") == "0"
        assert self.sql("""SELECT count(*) FROM repository_ref_projection p JOIN (
          SELECT DISTINCT ON (repository_id,ref_name) * FROM outbox_events
          ORDER BY repository_id,ref_name,storage_generation DESC,operation_sequence DESC,
          transaction_sequence DESC) e USING(repository_id,ref_name)
          WHERE p.event_id<>e.event_id OR p.oid<>e.new_oid""") == "0"
        assert self.sql("SELECT count(*) FROM repository_ref_projection") == self.sql(
            "SELECT count(DISTINCT (repository_id,ref_name)) FROM outbox_events")
        return {"events": events, "transactional_deliveries": events * 2,
                "same_ref_order_observed": True, "projection_matches_latest_receipt": True}

    def multiple_processes(self):
        self.push(count=8, branches=4)
        assert self.pending() == 64, "Service unexpectedly delivered without an external worker"
        for _ in range(4):
            self.spawn_worker()
        self.drain()
        self.push(count=4, branches=4)
        self.drain()
        owners = int(self.sql("SELECT count(DISTINCT owner) FROM test_delivery_trace WHERE state='leased'"))
        assert owners >= 2, "Did not observe multiple worker processes claim work"
        result = self.invariants()
        result.update(worker_processes=4, distinct_claim_owners=owners,
                      workers_have_no_git_or_storage=True, publication_precedes_workers=True)
        self.stop_workers()
        return result

    def independent_consumers(self):
        self.push(count=2, branches=4)
        audit = self.spawn_worker(consumers="audit-log")
        self.drain("audit-log")
        assert self.pending("ref-index") == 8
        self.kill_worker(audit)
        self.spawn_worker(consumers="ref-index")
        self.drain()
        self.stop_workers()
        # The one-shot command must also avoid Git/storage initialization.
        self.push()
        for consumer in ("audit-log", "ref-index"):
            self.run([self.args.binary, "worker-once"], env=self.worker_env(consumers=consumer))
        self.drain()
        return self.invariants()

    def consumer_failure_isolation(self):
        self.push(count=2, branches=2)
        self.sql("""CREATE FUNCTION test_reject_audit() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN RAISE EXCEPTION 'test audit consumer unavailable'; END $$;
            CREATE TRIGGER test_reject_audit BEFORE INSERT ON audit_events
            FOR EACH ROW EXECUTE FUNCTION test_reject_audit();""")
        self.spawn_worker()
        self.drain("ref-index", timeout=10)
        assert self.pending("audit-log") == 4
        self.until(lambda: int(self.sql("SELECT count(*) FROM event_deliveries WHERE consumer='audit-log' AND last_error_code='local_effect_failed'")) > 0,
                   "audit effect failure recorded")
        self.sql("DROP TRIGGER test_reject_audit ON audit_events; DROP FUNCTION test_reject_audit()")
        self.drain(timeout=15)
        self.stop_workers()
        result = self.invariants()
        result["ref_index_progressed_while_audit_effect_failed"] = True
        return result

    def killed_lease(self):
        self.push()
        self.sql("""CREATE FUNCTION test_pause_effect() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN PERFORM pg_sleep(6); RETURN NEW; END $$;
            CREATE TRIGGER test_pause_effect BEFORE INSERT ON audit_events
            FOR EACH ROW EXECUTE FUNCTION test_pause_effect();""")
        worker = self.spawn_worker(consumers="audit-log")
        self.until(lambda: self.sql("SELECT count(*) FROM event_deliveries WHERE state='leased' AND consumer='audit-log'") == "1",
                   "actual worker acquired durable lease")
        before = int(self.sql("SELECT count(*) FROM audit_events"))
        self.kill_worker(worker, hard=True)
        self.sql("DROP TRIGGER test_pause_effect ON audit_events; DROP FUNCTION test_pause_effect()")
        assert int(self.sql("SELECT count(*) FROM audit_events")) == before, "Killed transaction committed an effect"
        self.spawn_worker()
        self.drain()
        assert int(self.sql("SELECT count(*) FROM event_deliveries WHERE consumer='audit-log' AND attempts>=2 AND lease_generation>=2")) >= 1
        self.stop_workers()
        result = self.invariants()
        result.update(real_worker_sigkill=True, expired_lease_reclaimed=True,
                      deterministic_sql_pause_seconds=6)
        return result

    def redis_command(self, *parts):
        with socket.create_connection(("127.0.0.1", self.redis_port), timeout=2) as conn:
            data = [str(part).encode() if not isinstance(part, bytes) else part for part in parts]
            conn.sendall(b"*%d\r\n" % len(data) + b"".join(b"$%d\r\n" % len(p) + p + b"\r\n" for p in data))
            stream = conn.makefile("rb")
            def read():
                line = stream.readline(4096)
                assert line.endswith(b"\r\n"), "Incomplete Redis response"
                tag, value = line[:1], line[1:-2]
                if tag == b":": return int(value)
                if tag == b"+": return value
                if tag == b"$":
                    size = int(value)
                    assert 0 <= size <= 4096
                    return stream.read(size + 2)[:-2]
                if tag == b"*":
                    size = int(value)
                    assert 0 <= size <= 128
                    return [read() for _ in range(size)]
                raise AssertionError("Unexpected Redis response type")
            return read()

    def start_redis(self):
        self.redis_log = open(self.root / "redis.log", "ab")
        self.redis = subprocess.Popen([self.redis_binary, "--bind", "127.0.0.1", "--port", str(self.redis_port),
            "--save", "", "--appendonly", "no", "--protected-mode", "yes", "--dir", str(self.root)],
            stdout=self.redis_log, stderr=self.redis_log, start_new_session=True)
        def ready():
            assert self.redis.poll() is None, "Owned Redis server failed to start"
            try:
                return self.redis_command("PING") == b"PONG"
            except OSError:
                return False
        self.until(ready, "owned Redis readiness", 10)

    def stop_redis(self):
        self.stop_process(self.redis, hard=True)
        self.redis = None
        if self.redis_log:
            self.redis_log.close()
            self.redis_log = None

    def subscribers(self, expected=1):
        self.until(lambda: self.redis_command("PUBSUB", "NUMSUB", self.channel)[1] >= expected,
                   "Redis worker subscriber connected", 12)

    @staticmethod
    def resolve_redis():
        explicit = os.environ.get("ROOTYARD_TEST_REDIS_SERVER")
        candidate = shutil.which(explicit) if explicit is not None else shutil.which("redis-server")
        if explicit is not None and not candidate:
            raise AssertionError("Explicit ROOTYARD_TEST_REDIS_SERVER is not an executable; Redis coverage is required when configured")
        # Preserve the redis-server entrypoint name in argv[0]. Debian may link
        # it to a multicall redis-check-rdb binary, which selects its behavior
        # by argv[0]; resolving symlinks would launch the RDB checker instead.
        return os.path.abspath(candidate) if candidate else None

    def redis_recovery(self):
        self.redis_binary = self.resolve_redis()
        if not self.redis_binary:
            return {"skip": "redis-server unavailable; set ROOTYARD_TEST_REDIS_SERVER to an executable (CI must install Redis)"}
        self.runtime["redis_server"] = self.run([self.redis_binary, "--version"]).stdout.decode().strip()
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.redis_port = sock.getsockname()[1]
        self.start_redis()
        self.stop()
        self.env.update(ROOTYARD_WAKE_TRANSPORT="redis", ROOTYARD_REDIS_ADDRESS="127.0.0.1:" + str(self.redis_port),
                        ROOTYARD_WAKE_CHANNEL=self.channel)
        self.start()
        assert self.redis_command("PUBSUB", "NUMSUB", self.channel)[1] == 0
        self.push(count=2)
        self.spawn_worker(transport="redis", poll=200)
        self.subscribers()
        self.drain()
        before_hints = self.sql("SELECT count(*) FROM outbox_events")
        for payload in [b"v1"] * 20 + [b"wrong-version", b'{"event_id":"forged"}', b"x" * 512]:
            self.redis_command("PUBLISH", self.channel, payload)
        self.redis_command("PUBLISH", self.channel + ":wrong", "v1")
        time.sleep(.2)
        assert self.sql("SELECT count(*) FROM outbox_events") == before_hints
        self.invariants()
        self.push(count=2)
        self.drain()
        self.subscribers()
        self.stop_redis()
        self.push(count=2)
        self.drain()  # Only the independently scheduled PG poll can recover.
        self.start_redis()
        self.subscribers()
        self.push(count=2)
        self.drain()
        self.stop_workers()
        # A long interval makes timely delivery evidence for the service's Redis
        # wake publication rather than the periodic polling safety net.
        self.spawn_worker(transport="redis", poll=60000)
        self.subscribers()
        time.sleep(.3)
        self.push()
        self.drain(timeout=5)
        self.stop_workers()
        result = self.invariants()
        result.update(publication_without_subscribers=True, duplicate_and_wrong_hints_harmless=True,
                      redis_sigkill_polling_recovery=True, redis_restart_resubscribed=True,
                      redis_wake_before_sixty_second_poll=True)
        return result

    def cleanup(self):
        self.stop_workers()
        self.stop_redis()
        super().cleanup()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("ROOTYARD_TEST_DATABASE_URL is required")
    for executable in ("git", "psql", args.binary):
        if not shutil.which(executable):
            parser.error("Required executable not found: " + executable)
    h = CrossProcessHarness(args)
    success = False
    binary_sha = hashlib.sha256(Path(args.binary).read_bytes()).hexdigest()
    try:
        h.runtime.update(git_client=h.run(["git", "--version"]).stdout.decode().strip(),
                         git_server=h.run([h.env.get("ROOTYARD_GIT", "git"), "--version"]).stdout.decode().strip(),
                         psql=h.run(["psql", "--version"]).stdout.decode().strip())
        for name, case in [("isolated_service_without_embedded_worker", h.fixture),
                           ("four_external_workers_exact_effects_and_order", h.multiple_processes),
                           ("independent_consumers_and_pg_only_worker_once", h.independent_consumers),
                           ("failing_audit_does_not_block_ref_index", h.consumer_failure_isolation),
                           ("sigkill_actual_worker_expired_lease_recovery", h.killed_lease),
                           ("real_redis_lost_duplicate_hints_disconnect_reconnect", h.redis_recovery)]:
            h.case(name, case)
            if isinstance(h.results[-1].get("detail"), dict) and "skip" in h.results[-1]["detail"]:
                h.results[-1]["status"] = "skipped"
                print(name + ": skipped: " + h.results[-1]["detail"]["skip"], flush=True)
        success = True
    except Exception as error:
        print(h.redact(error), file=sys.stderr)
        # Logs are redacted and bounded; neither environment nor command lines
        # are included, because either may contain database credentials/tokens.
        for log in sorted(h.root.glob("*.log")):
            print(h.redact(log.name + ": " + log.read_text(errors="replace")[-3000:]), file=sys.stderr)
    finally:
        try:
            h.cleanup()
        except Exception as error:
            h.results.append(dict(name="cleanup", status="failed", error=h.redact(error)))
            success = False
        report = dict(passed=success, cases=h.results, limitations=h.limits,
                      runtime=dict(binary_sha256=binary_sha, **h.runtime),
                      redis_coverage=next((r["status"] for r in h.results if r["name"].startswith("real_redis")), "not_run"))
        if args.keep:
            report["retained_directory"] = str(h.root)
        text = h.redact(json.dumps(report, indent=2)) + "\n"
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(text)
        print(text)
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
