#!/usr/bin/env python3
"""Native Issue #33 acceptance: durable background webhook worker.

Real Rust service, disposable PostgreSQL 17 and an owned loopback HTTP receiver.
This file never calls ``/webhooks/dispatch``: every delivery, retry and PR
synchronization below must be produced by the service's own background worker.

Faults are real process faults: the worker process group is SIGKILLed after a
pending row is enqueued, and again after the receiver answered 2xx but before
the row completion committed (the ack window is widened with a real PostgreSQL
``SELECT ... FOR UPDATE`` row lock, never by forging delivery state). Recovery
waits out the documented lease (``ceil(timeout_ms/1000) + 5`` seconds) and the
documented exponential backoff (base 2s) in real time.
"""
import argparse
import hashlib
import http.server
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from webhooks import WebhooksHarness  # noqa: E402

SECRET = "synthetic-worker-secret-0123456789"


class Receiver:
    """Owned loopback HTTP receiver with per-marker holds, failures and records."""

    def __init__(self):
        self.requests = []
        self.lock = threading.Lock()
        self.holds = {}
        self.fails = set()
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self):
                raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                try:
                    body = json.loads(raw.decode("utf-8")) if raw else {}
                except Exception:
                    body = {}
                marker = body.get("zen")
                with outer.lock:
                    outer.requests.append({
                        "delivery": self.headers.get("X-Rootyard-Delivery"),
                        "attempt": int(self.headers.get("X-Rootyard-Attempt", "0")),
                        "event": self.headers.get("X-Rootyard-Event"),
                        "signature": self.headers.get("X-Rootyard-Signature-256"),
                        "body": body,
                    })
                    hold = outer.holds.get(marker)
                    first = bool(hold) and not hold["hit"]
                    if first:
                        hold["hit"] = True
                    status = 500 if marker in outer.fails else 204
                if first:
                    hold["event"].wait(30)
                try:
                    self.send_response(status)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                except OSError:
                    pass  # the killed worker may already have dropped the socket

            def log_message(self, *_):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server.server_port}/hook"

    def hold(self, marker):
        gate = {"event": threading.Event(), "hit": False}
        with self.lock:
            self.holds[marker] = gate
        return gate

    def fail(self, marker):
        with self.lock:
            self.fails.add(marker)

    def matching(self, marker):
        with self.lock:
            return [r for r in self.requests if r["body"].get("zen") == marker]

    def attempts(self, marker):
        return [r["attempt"] for r in self.matching(marker)]

    def events(self, event_type, head_oid=None):
        with self.lock:
            return [r for r in self.requests if r["event"] == event_type
                    and (head_oid is None or r["body"].get("head_oid") == head_oid)]

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


def wait_for(label, fn, timeout=25.0, interval=0.2):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        value = fn()
        if value:
            return value
        time.sleep(interval)
    raise AssertionError(f"timeout after {timeout}s waiting for {label}")


class RowLock:
    """Holds a real PostgreSQL row lock so a sent delivery cannot be acknowledged."""

    def __init__(self, database, delivery_id):
        self.database = database
        self.delivery_id = delivery_id
        self.proc = None
        self.backend_pid = None

    def acquire(self):
        self.proc = subprocess.Popen(
            ["psql", "--dbname", self.database, "-X", "-q", "-v", "ON_ERROR_STOP=1", "-At"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        script = ("BEGIN;\nSELECT pg_backend_pid();\n"
                  f"SELECT id FROM forge_webhook_deliveries WHERE id='{self.delivery_id}' FOR UPDATE;\n")
        try:
            self.proc.stdin.write(script.encode())
            self.proc.stdin.flush()
            self.backend_pid = int(self.proc.stdout.readline().decode().strip())
            locked = self.proc.stdout.readline().decode().strip()
            assert locked == self.delivery_id, ("row lock not acquired", locked)
        except Exception:
            self.release()
            raise
        return self

    def release(self):
        if self.proc is None:
            return
        try:
            self.proc.stdin.write(b"ROLLBACK;\n")
            self.proc.stdin.flush()
            self.proc.stdin.close()
        except (OSError, ValueError):
            pass
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.proc = None


def production_digest(root):
    """Same all-file map as round4 source_digest.py for exact baseline comparison."""
    paths = set()
    for directory in ("src", "migrations", "schema"):
        paths.update(p for p in (root / directory).rglob("*") if p.is_file())
    for name in ("Cargo.toml", "Cargo.lock", "build.rs", ".cargo/config.toml"):
        if (root / name).is_file():
            paths.add(root / name)
    files = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
             for p in sorted(paths)}
    encoded = json.dumps(files, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest(), len(files)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--expect-production-digest", default=None)
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("ROOTYARD_TEST_DATABASE_URL is required; use a dedicated test database")
    repo_root = Path(__file__).resolve().parents[1]
    digest, file_count = production_digest(repo_root)
    if args.expect_production_digest and args.expect_production_digest != digest:
        parser.error("production source differs from the expected baseline digest")

    h = WebhooksHarness(args)
    h.env["ROOTYARD_OUTBOX_WORKER"] = "false"
    receiver = Receiver()
    cases = []
    report = {
        "issue": 33,
        "binary": args.binary,
        "binary_sha256": hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
        "source_head": subprocess.run(["git", "-C", str(repo_root), "rev-parse", "HEAD"],
                                      stdout=subprocess.PIPE, check=True).stdout.decode().strip(),
        "production_inputs_sha256": digest,
        "production_file_count": file_count,
        "manual_dispatch_calls": 0,
        "cases": cases,
    }
    row_lock = None
    success = False

    def case(name, fn):
        start = time.monotonic()
        try:
            detail = fn()
            cases.append(dict(name=name, status="passed", seconds=round(time.monotonic() - start, 3), detail=detail))
            print(name + ": passed", flush=True)
        except Exception as error:
            cases.append(dict(name=name, status="failed", seconds=round(time.monotonic() - start, 3), error=h.redact(error)))
            raise

    def delivery(hook_id, delivery_id):
        return h.document(f"{h.webhookspath}/{hook_id}/deliveries/{delivery_id}")

    def hook(body):
        body = {"secret": SECRET, "auto_ci_pin": False, "timeout_ms": 2000, **body}
        return h.document(h.webhookspath, 201, method="POST", body=body)

    def enqueue_boundary():
        """Enqueued row without a running worker is delivered after restart."""
        ping_hook = hook({"url": receiver.url, "events": ["ping"], "max_attempts": 3})
        marker = "issue33-enqueue-boundary"
        pending = h.document(f"{h.webhookspath}/{ping_hook['id']}/ping", method="POST",
                             body={"deliver_now": False, "zen": marker, "event_id": "issue33-enqueue-1"})
        assert pending["state"] == "pending" and pending["attempts"] == 0, pending
        time.sleep(2.5)
        assert receiver.matching(marker) == [], "payload was sent while the worker was disabled"
        h.stop(hard=True)
        h.env["ROOTYARD_OUTBOX_WORKER"] = "true"
        h.start()
        wait_for("durable scan to recover the enqueued row", lambda: receiver.matching(marker))
        done = wait_for("delivered state", lambda: (lambda d: d if d["state"] == "delivered" else None)(
            delivery(ping_hook["id"], pending["id"])))
        assert done["attempts"] == 1, done
        return {"delivery_id": done["id"], "state_after_enqueue_without_worker": "pending",
                "recovered_state": done["state"], "attempts": done["attempts"],
                "receiver_attempts": receiver.attempts(marker), "manual_dispatch_calls": 0}

    def ack_boundary():
        """SIGKILL after a 2xx response but before completion commits; recover at-least-once."""
        nonlocal row_lock
        ack_hook = hook({"url": receiver.url, "events": ["ping"], "max_attempts": 3})
        marker = "issue33-ack-boundary"
        gate = receiver.hold(marker)
        pending = h.document(f"{h.webhookspath}/{ack_hook['id']}/ping", method="POST",
                             body={"deliver_now": False, "zen": marker, "event_id": "issue33-ack-1"})
        wait_for("worker to claim and send", lambda: receiver.matching(marker))
        leased = delivery(ack_hook["id"], pending["id"])
        assert leased["state"] == "leased", leased
        row_lock = RowLock(h.db, pending["id"])
        row_lock.acquire()
        gate["event"].set()  # receiver answers 204; completion now blocks on the row lock
        time.sleep(0.8)
        waiting = h.sql("SELECT count(*) FROM pg_stat_activity WHERE wait_event_type='Lock' "
                        "AND query ILIKE 'UPDATE forge_webhook_deliveries%'")
        blocked = delivery(ack_hook["id"], pending["id"])
        assert waiting == "1" and blocked["state"] == "leased" and blocked["attempts"] == 1, (waiting, blocked)
        killed_pid = h.proc.pid
        h.stop(hard=True)
        # A backend already blocked in the completion UPDATE may only notice the
        # client's death after it acquires the lock, so terminate the dead
        # worker's own backend before releasing the row lock.
        terminated = h.sql("SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity "
                           "WHERE wait_event_type='Lock' AND query ILIKE 'UPDATE forge_webhook_deliveries%'")
        row_lock.release()
        row_lock = None
        durable = h.sql(f"SELECT state || ',' || attempts FROM forge_webhook_deliveries WHERE id='{pending['id']}'")
        assert durable == "leased,1", (durable, terminated)
        h.start()
        wait_for("at-least-once retry after the real lease expiry",
                 lambda: len(receiver.matching(marker)) >= 2, timeout=30)
        done = wait_for("delivered after restart", lambda: (lambda d: d if d["state"] == "delivered" else None)(
            delivery(ack_hook["id"], pending["id"])))
        attempts = receiver.attempts(marker)
        assert done["attempts"] == 2 and attempts[:2] == [1, 2], (done, attempts)
        delivery_ids = {r["delivery"] for r in receiver.matching(marker)}
        assert delivery_ids == {pending["id"]}, delivery_ids
        return {"delivery_id": pending["id"], "killed_worker_pid": killed_pid,
                "state_before_kill": "leased", "durable_state_after_kill": durable, "dead_worker_backends_terminated": terminated,
                "receiver_status_first_attempt": 204, "receiver_attempts": attempts[:2],
                "duplicate_delivery_id": pending["id"], "attempts": done["attempts"],
                "recovered_state": done["state"], "manual_dispatch_calls": 0}

    def retry_overlap():
        """A manual retry cannot steal a live worker lease."""
        overlap_hook = hook({"url": receiver.url, "events": ["ping"], "max_attempts": 3, "timeout_ms": 5000})
        marker = "issue33-retry-overlap"
        gate = receiver.hold(marker)
        pending = h.document(f"{h.webhookspath}/{overlap_hook['id']}/ping", method="POST",
                             body={"deliver_now": False, "zen": marker, "event_id": "issue33-overlap-1"})
        wait_for("worker to claim the overlapping delivery", lambda: receiver.matching(marker))
        status, raw, _ = h.http(f"{h.webhookspath}/{overlap_hook['id']}/deliveries/{pending['id']}/retry",
                                token=h.alice, method="POST", body={"deliver_now": False})
        assert status == 409, (status, raw[:300])
        gate["event"].set()
        done = wait_for("delivered by the owning attempt", lambda: (lambda d: d if d["state"] == "delivered" else None)(
            delivery(overlap_hook["id"], pending["id"])))
        assert done["attempts"] == 1, done
        return {"delivery_id": pending["id"], "retry_while_leased_http": status,
                "receiver_attempts": receiver.attempts(marker), "final_attempts": done["attempts"],
                "final_state": done["state"], "manual_dispatch_calls": 0}

    def automatic_backoff_and_dead_letter():
        """A failed delivery is retried and exhausted by the worker in real time."""
        retry_hook = hook({"url": receiver.url, "events": ["ping"], "max_attempts": 2})
        marker = "issue33-backoff-deadletter"
        receiver.fail(marker)
        pending = h.document(f"{h.webhookspath}/{retry_hook['id']}/ping", method="POST",
                             body={"deliver_now": False, "zen": marker, "event_id": "issue33-backoff-1"})
        failed = wait_for("first automatic failed attempt", lambda: (lambda d: d if d["state"] == "failed" else None)(
            delivery(retry_hook["id"], pending["id"])))
        assert failed["attempts"] == 1 and failed["last_error"] == "HTTP 500", failed
        backoff = failed["next_attempt_unix"] - int(time.time())
        assert 1 <= backoff <= 5, (backoff, failed)
        started = time.monotonic()
        dead = wait_for("exhausted delivery to reach dead_letter", lambda: (lambda d: d if d["state"] == "dead_letter" else None)(
            delivery(retry_hook["id"], pending["id"])), timeout=20)
        elapsed = time.monotonic() - started
        assert dead["attempts"] == 2 and dead["last_error"] == "HTTP 500", dead
        assert elapsed >= 1.0, elapsed
        attempts = receiver.attempts(marker)
        assert attempts[:2] == [1, 2], attempts
        listed = h.document(f"{h.webhookspath}/{retry_hook['id']}/deliveries?state=dead_letter")
        assert any(d["id"] == pending["id"] for d in listed["items"]), listed
        return {"delivery_id": pending["id"], "state_after_first_attempt": failed["state"],
                "attempts_after_first_attempt": failed["attempts"], "scheduled_backoff_seconds": backoff,
                "real_dead_letter_delay_seconds": round(elapsed, 3), "dead_letter_state": dead["state"],
                "final_attempts": dead["attempts"], "receiver_attempts": attempts[:2],
                "observable_via": "/deliveries?state=dead_letter", "manual_dispatch_calls": 0}

    def push_updates_open_pull():
        """A stock Git push updates an open PR: new pin, queued check and receiver delivery."""
        h.document(h.webhookspath, 201, method="POST", body={
            "url": receiver.url, "secret": SECRET, "events": ["pull_request"],
            "ci_contexts": ["ci/test"], "auto_ci_pin": True})
        pr = h.document(h.pullspath, 201, method="POST", body={
            "title": "worker automatic sync", "body": "issue33 automatic",
            "head_ref": "refs/heads/feature", "base_ref": "refs/heads/main"})
        assert pr["head_oid"] == h.feat1_oid, pr
        repo = pr["repository_id"]
        bare = h.root / "data" / "repos" / (repo + ".git")
        run_filter = (f"WHERE repository_id='{repo}' AND pull_number={pr['number']} "
                      "AND context='ci/test'")
        wait_for("initial queued ci_runs row", lambda: h.sql(
            f"SELECT count(*) FROM ci_runs {run_filter} AND head_oid='{h.feat1_oid}' AND state='queued'") == "1")
        old_job = h.sql(f"SELECT job_id FROM ci_runs {run_filter} AND head_oid='{h.feat1_oid}'")
        old_pin = h.git("--git-dir=" + str(bare), "rev-parse", "refs/rootyard-ci/jobs/" + old_job).stdout.decode().strip()
        assert old_pin == h.feat1_oid, (old_pin, h.feat1_oid)

        h.git("checkout", "feature", cwd=h.work)
        (h.work / "feature.txt").write_text("worker automatic sync\n")
        h.git("commit", "-am", "worker automatic sync", cwd=h.work)
        new_oid = h.git("rev-parse", "HEAD", cwd=h.work).stdout.decode().strip()
        h.git("push", "origin", "HEAD:refs/heads/feature", cwd=h.work, token=h.alice)

        updated = wait_for("background worker to advance the open PR", lambda: (
            lambda p: p if p["head_oid"] == new_oid and p["version"] > pr["version"] else None)(
                h.document(f"{h.pullspath}/{pr['number']}")), timeout=30)
        new_job = wait_for("new queued ci_runs row", lambda: h.sql(
            f"SELECT job_id FROM ci_runs {run_filter} AND head_oid='{new_oid}' AND state='queued'") or None, timeout=30)
        pin_oid = wait_for("new immutable CI pin ref", lambda: (
            lambda oid: oid if oid == new_oid else None)(
                h.git("--git-dir=" + str(bare), "rev-parse", "refs/rootyard-ci/jobs/" + new_job).stdout.decode().strip()))
        wait_for("queued check run for the new head", lambda: h.sql(
            f"SELECT count(*) FROM forge_check_runs WHERE repository_id='{repo}' "
            f"AND commit_oid='{new_oid}' AND context='ci/test' AND status='queued'") == "1")
        delivered = wait_for("automatic pull_request delivery for the new head",
                             lambda: receiver.events("pull_request", new_oid) or None, timeout=30)
        assert any(r["body"].get("action") == "synchronize" for r in delivered), delivered
        assert (delivered[0]["body"].get("ci_pin") or {}).get("job_id") == new_job, delivered[0]["body"]
        assert old_job != new_job and old_pin != new_oid
        return {"repository_id": repo, "old_pin_oid": old_pin, "push_head_oid": new_oid,
                "new_pin_job_id": new_job, "new_pin_ref": "refs/rootyard-ci/jobs/" + new_job,
                "new_pin_oid": pin_oid, "pull_version_before": pr["version"],
                "pull_version_after": updated["version"], "queued_check_context": "ci/test",
                "receiver_event": delivered[0]["event"],
                "receiver_action": delivered[0]["body"].get("action"),
                "receiver_delivery_id": delivered[0]["delivery"], "manual_dispatch_calls": 0}

    try:
        h.setup()
        case("enqueue_boundary_lost_wakeup_recovers", enqueue_boundary)
        case("kill_after_receiver_2xx_before_ack_recovers_at_least_once", ack_boundary)
        case("retry_cannot_steal_a_live_worker_lease", retry_overlap)
        case("automatic_backoff_retry_and_dead_letter", automatic_backoff_and_dead_letter)
        case("stock_push_updates_open_pull_automatically", push_updates_open_pull)
        success = True
    except Exception as error:
        print(h.redact(error), file=sys.stderr)
    finally:
        if row_lock is not None:
            row_lock.release()
        receiver.close()
        try:
            h.cleanup()
        except Exception as error:
            cases.append(dict(name="cleanup", status="failed", error=h.redact(error)))
            success = False
        report["passed"] = success
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
