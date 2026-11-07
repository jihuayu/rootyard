#!/usr/bin/env python3
"""Native issue #72 regression: fair, bounded background webhook scheduling.

The real Rust service runs with its own background worker. No
``/webhooks/dispatch`` call exists in this file, so delivery, retry, restart and
cancellation behaviour must come from the durable worker.

The early repository in ``(tenant_id, repository_id)`` order is held at a real
loopback receiver before a later healthy repository is allowed to deliver. The
later delivery must complete while the early request is still held, proving that
a slow receiver does not take the whole scan. All timings are observations from
one host; they are not a throughput certification.
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
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from webhooks import WebhooksHarness  # noqa: E402

SECRET = "fairness-native-secret-0123456789"


def request_key(body):
    """Ping events carry ``zen``; push backfill events carry ``ref_name``."""
    return body.get("zen") or body.get("ref_name")


class Receiver:
    """Owned loopback receiver with per-marker hold, failure and delay."""

    def __init__(self):
        self.requests = []
        self.lock = threading.Lock()
        self.holds = {}
        self.fails = set()
        self.delays = {}
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self):
                raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                try:
                    body = json.loads(raw.decode("utf-8")) if raw else {}
                except Exception:
                    body = {}
                marker = request_key(body)
                with outer.lock:
                    outer.requests.append({
                        "delivery": self.headers.get("X-Rootyard-Delivery"),
                        "attempt": int(self.headers.get("X-Rootyard-Attempt", "0")),
                        "event": self.headers.get("X-Rootyard-Event"),
                        "body": body,
                    })
                    hold = outer.holds.get(marker)
                    first = bool(hold) and not hold["hit"]
                    if first:
                        hold["hit"] = True
                    status = 500 if marker in outer.fails else 204
                    delay = outer.delays.get(marker, 0.0)
                if first:
                    hold["event"].wait(30)
                if delay:
                    time.sleep(delay)
                try:
                    self.send_response(status)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                except OSError:
                    pass

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

    def delay(self, marker, seconds):
        with self.lock:
            self.delays[marker] = seconds

    def matching(self, marker):
        with self.lock:
            return [r for r in self.requests if request_key(r["body"]) == marker]

    def attempts(self, marker):
        return [r["attempt"] for r in self.matching(marker)]

    def delivery_ids(self, marker):
        return {r["delivery"] for r in self.matching(marker)}

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


def wait_for(label, fn, timeout=25.0, interval=0.1):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        value = fn()
        if value:
            return value
        time.sleep(interval)
    raise AssertionError(f"timeout after {timeout}s waiting for {label}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("ROOTYARD_TEST_DATABASE_URL is required; use a dedicated test database")

    repo_root = Path(__file__).resolve().parents[1]
    harness = WebhooksHarness(args)
    receiver = Receiver()
    cases = []
    report = {
        "issue": 72,
        "binary": args.binary,
        "binary_sha256": hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
        "source_head": subprocess.run(
            ["git", "-C", str(repo_root), "rev-parse", "HEAD"],
            stdout=subprocess.PIPE, check=True,
        ).stdout.decode().strip(),
        "manual_dispatch_calls": 0,
        "cases": cases,
    }
    success = False

    def case(name, fn):
        started = time.monotonic()
        try:
            detail = fn()
            cases.append(dict(name=name, status="passed", seconds=round(time.monotonic() - started, 3), detail=detail))
            print(name + ": passed", flush=True)
        except Exception as error:
            cases.append(dict(name=name, status="failed", seconds=round(time.monotonic() - started, 3),
                              error=harness.redact(error)))
            raise

    def worker(enabled):
        harness.stop()
        harness.env["ROOTYARD_OUTBOX_WORKER"] = "true" if enabled else "false"
        harness.start()

    def hook(repo_name, events, timeout_ms=3000, max_attempts=3):
        return harness.document(
            f"/api/repos/alice/{repo_name}/webhooks", 201, method="POST",
            body={"url": receiver.url, "secret": SECRET, "events": events,
                  "auto_ci_pin": False, "timeout_ms": timeout_ms,
                  "max_attempts": max_attempts},
        )

    def ping(repo_name, hook_id, marker, event_id):
        return harness.document(
            f"/api/repos/alice/{repo_name}/webhooks/{hook_id}/ping", 200, method="POST",
            body={"zen": marker, "event_id": event_id, "deliver_now": False},
        )

    def delivery(repo_name, hook_id, delivery_id):
        return harness.document(f"/api/repos/alice/{repo_name}/webhooks/{hook_id}/deliveries/{delivery_id}")

    def row_state(delivery_id):
        return harness.sql(
            "SELECT state || ',' || attempts FROM forge_webhook_deliveries "
            f"WHERE id='{delivery_id}'")

    def db_delivery(delivery_id):
        row = row_state(delivery_id)
        assert row, f"missing delivery row {delivery_id}"
        state, attempts = row.split(",")
        return {"state": state, "attempts": int(attempts)}

    def two_sorted_repositories():
        worker(False)
        # WebhooksHarness.setup already seeds both repositories (including
        # alice/other), so only their IDs are needed to fix the sorted order.
        repos = sorted([("forge", harness.repo["id"]), ("other", harness.other["id"])], key=lambda pair: pair[1])
        early_name, later_name = repos[0][0], repos[1][0]
        early_hook = hook(early_name, ["ping"])
        later_hook = hook(later_name, ["ping"])
        early_marker = "fair-early-slow"
        later_marker = "fair-later-fast"
        early_delivery = ping(early_name, early_hook["id"], early_marker, "fair-early-1")
        later_delivery = ping(later_name, later_hook["id"], later_marker, "fair-later-1")
        gate = receiver.hold(early_marker)
        worker(True)

        wait_for("early sorted repository to claim and hold its receiver", lambda: receiver.matching(early_marker), timeout=15)
        assert gate["hit"], "held receiver was never entered"
        fast_started = time.monotonic()
        wait_for("later healthy repository delivery while early receiver is held",
                 lambda: receiver.matching(later_marker), timeout=8)
        fast_seconds = round(time.monotonic() - fast_started, 3)
        assert not gate["event"].is_set(), "slow receiver was released before the fairness assertion"
        wait_for("later fast delivery state", lambda: (
            lambda d: d if d["state"] == "delivered" else None
        )(delivery(later_name, later_hook["id"], later_delivery["id"])))
        early_now = delivery(early_name, early_hook["id"], early_delivery["id"])
        assert early_now["state"] in ("pending", "leased", "failed"), early_now
        assert not gate["event"].is_set(), "slow receiver was released before checking the early row"
        gate["event"].set()
        early_done = wait_for("early delivery after release", lambda: (
            lambda d: d if d["state"] == "delivered" else None
        )(delivery(early_name, early_hook["id"], early_delivery["id"])), timeout=30)
        assert receiver.attempts(later_marker) == [1], receiver.attempts(later_marker)
        assert early_done["attempts"] <= 2, early_done
        return {
            "sorted_order": [early_name, later_name],
            "early_receiver_was_held": True,
            "later_fast_delivery_seconds_while_held": fast_seconds,
            "later_state_while_early_held": "delivered",
            "early_state_while_held": early_now["state"],
            "early_final_attempts": early_done["attempts"],
            "later_final_attempts": receiver.attempts(later_marker),
        }

    def large_outbox_fanout_keeps_later_repo_live():
        worker(False)
        # Five fresh repositories; sort by UUID to match the scheduler's
        # (tenant_id,repository_id) order. The first four get a large
        # outbox x hook fanout, the last is a healthy repository behind them.
        created = []
        for index in range(5):
            name = f"fairfan{index}"
            created.append((name, harness.document(
                "/api/repos", 201, method="POST", body={"name": name})))
        created.sort(key=lambda item: item[1]["id"])
        fanout, (healthy_name, _healthy_repo) = created[:4], created[4]
        fanout_ids = [repo["id"] for _, repo in fanout]
        hook_count = 512
        event_count = 200
        for index, (_name, repo) in enumerate(fanout):
            operation = uuid.uuid4()
            storage = int(harness.sql(
                f"SELECT storage_generation FROM repositories WHERE id='{repo['id']}'"))
            harness.sql(
                "INSERT INTO git_operations(id,repository_id,actor_id,token_id,"
                "actor_name,sequence,storage_generation,evidence,outcome) "
                f"VALUES('{operation}','{repo['id']}','{harness.alice['user_id']}',"
                f"'{harness.alice['token_id']}','alice',1000,{storage},'{{}}','recorded')")
            harness.sql(
                "INSERT INTO outbox_events(event_id,operation_id,repository_id,"
                "storage_generation,operation_sequence,transaction_sequence,"
                "ref_name,old_oid,new_oid) "
                f"SELECT md5('fairfan-{index}-'||g::text)||md5('event-'||g::text),"
                f"'{operation}','{repo['id']}',{storage},1000,g,"
                f"'refs/heads/fanout-{index}-'||g,repeat('0',40),repeat('a',40) "
                f"FROM generate_series(1,{event_count}) g")
            harness.sql(
                "INSERT INTO forge_webhooks(id,tenant_id,repository_id,url,secret,"
                "secret_sha256,events,ci_contexts,auto_ci_pin,active,max_attempts,"
                "timeout_ms) "
                f"SELECT gen_random_uuid(),'{harness.alice['user_id']}',"
                f"'{repo['id']}','{receiver.url}','fairfan-secret-{index}',"
                "repeat('a',64),jsonb_build_array('push'),jsonb_build_array('ci/default'),"
                f"false,true,2,30000 FROM generate_series(1,{hook_count})")

        # Only the first fanout repository's first ref is held. Array ordering
        # makes that ref the first events x hook page, so exactly one
        # legitimate in-flight request is parked while the backlog persists.
        held_ref = "refs/heads/fanout-0-1"
        gate = receiver.hold(held_ref)
        healthy_hook = hook(healthy_name, ["ping"], timeout_ms=3000, max_attempts=3)
        healthy_marker = "healthy-while-fanout-backlog"
        healthy_delivery = ping(healthy_name, healthy_hook["id"], healthy_marker, "healthy-fanout-1")
        worker(True)

        held = wait_for("held fanout receiver", lambda: receiver.matching(held_ref), timeout=30)
        held_id = held[0]["delivery"]
        assert gate["hit"], "held fanout receiver was never entered"
        leased = db_delivery(held_id)
        assert leased["state"] == "leased" and leased["attempts"] == 1, leased

        started = time.monotonic()
        healthy_done = wait_for("healthy repository delivery while fanout backlog exists", lambda: (
            lambda row: row if row["state"] == "delivered" else None
        )(db_delivery(healthy_delivery["id"])), timeout=25)
        elapsed = round(time.monotonic() - started, 3)
        assert healthy_done["attempts"] == 1, healthy_done
        assert receiver.attempts(healthy_marker) == [1], receiver.attempts(healthy_marker)
        assert not gate["event"].is_set(), "held fanout receiver released before the fairness assertion"

        fanout_rows = int(harness.sql(
            "SELECT count(*) FROM forge_webhook_deliveries WHERE event_type='push' "
            "AND repository_id IN (" + ",".join(f"'{repo_id}'" for repo_id in fanout_ids) + ")"))
        total_pairs = len(fanout_ids) * hook_count * event_count
        assert 0 < fanout_rows < total_pairs, (fanout_rows, total_pairs)
        held_still = db_delivery(held_id)
        assert held_still["state"] == "leased" and held_still["attempts"] == 1, held_still

        gate["event"].set()
        held_done = wait_for("held fanout delivery after release", lambda: (
            lambda row: row if row["state"] == "delivered" else None
        )(db_delivery(held_id)), timeout=40)
        assert held_done["attempts"] == 1, held_done
        held_attempts = [request["attempt"] for request in receiver.matching(held_ref)
                         if request["delivery"] == held_id]
        assert held_attempts == [1], held_attempts
        return {
            "fanout_repositories": len(fanout_ids),
            "hooks_per_fanout_repository": hook_count,
            "outbox_events_per_fanout_repository": event_count,
            "hook_event_pairs_available": total_pairs,
            "push_delivery_rows_while_healthy_delivered": fanout_rows,
            "healthy_delivery_seconds_while_fanout_held": elapsed,
            "healthy_attempts": healthy_done["attempts"],
            "held_delivery_attempts": held_done["attempts"],
            "held_delivery_id": held_id,
        }

    def small_backfill_pages_and_drains_over_rounds():
        worker(False)
        repo = harness.document("/api/repos", 201, method="POST", body={"name": "fairpage"})
        hook_count = 8
        event_count = 17
        missing_pairs = hook_count * event_count
        # Deliberately just above one OUTBOX_BACKFILL_LIMIT page. A second round
        # must select the remainder, and later rounds must drain the delivery
        # rows. No manual dispatch is called anywhere in this file.
        assert 128 < missing_pairs < 200, missing_pairs
        operation = uuid.uuid4()
        storage = int(harness.sql(
            f"SELECT storage_generation FROM repositories WHERE id='{repo['id']}'"))
        harness.sql(
            "INSERT INTO git_operations(id,repository_id,actor_id,token_id,"
            "actor_name,sequence,storage_generation,evidence,outcome) "
            f"VALUES('{operation}','{repo['id']}','{harness.alice['user_id']}',"
            f"'{harness.alice['token_id']}','alice',1000,{storage},'{{}}','recorded')")
        harness.sql(
            "INSERT INTO outbox_events(event_id,operation_id,repository_id,"
            "storage_generation,operation_sequence,transaction_sequence,"
            "ref_name,old_oid,new_oid) "
            "SELECT md5('fairpage-'||g::text)||md5('event-'||g::text),"
            f"'{operation}','{repo['id']}',{storage},1000,g,"
            "'refs/heads/page-'||g,repeat('0',40),repeat('a',40) "
            f"FROM generate_series(1,{event_count}) g")
        harness.sql(
            "INSERT INTO forge_webhooks(id,tenant_id,repository_id,url,secret,"
            "secret_sha256,events,ci_contexts,auto_ci_pin,active,max_attempts,"
            "timeout_ms) "
            f"SELECT gen_random_uuid(),'{harness.alice['user_id']}',"
            f"'{repo['id']}','{receiver.url}','fairpage-secret',"
            "repeat('a',64),jsonb_build_array('push'),jsonb_build_array('ci/default'),"
            f"false,true,2,3000 FROM generate_series(1,{hook_count})")

        def push_rows():
            return int(harness.sql(
                "SELECT count(*) FROM forge_webhook_deliveries WHERE event_type='push' "
                f"AND repository_id='{repo['id']}'"))

        def delivered_rows():
            return int(harness.sql(
                "SELECT count(*) FROM forge_webhook_deliveries WHERE event_type='push' "
                f"AND repository_id='{repo['id']}' AND state='delivered'"))

        worker(True)
        first_page = wait_for("first bounded backfill page", lambda: (
            lambda rows: rows if rows >= 128 else None)(push_rows()), timeout=30)
        assert first_page == 128, first_page
        assert first_page < missing_pairs, (first_page, missing_pairs)
        next_page = wait_for("next backfill page selected in a later round", lambda: (
            lambda rows: rows if rows == missing_pairs else None)(push_rows()), timeout=60)
        delivered_after_next_page = delivered_rows()
        assert 0 < delivered_after_next_page <= 8, delivered_after_next_page
        later_round = wait_for("delivery drain advances in later rounds", lambda: (
            lambda rows: rows if rows >= delivered_after_next_page + 8 else None)(
                delivered_rows()), timeout=60)
        delivered_total = wait_for("all bounded pairs delivered over rounds", lambda: (
            lambda rows: rows if rows == missing_pairs else None)(delivered_rows()), timeout=120)
        assert receiver.attempts("refs/heads/page-1"), "receiver never saw a backfilled push event"
        return {
            "outbox_events": event_count,
            "active_hooks": hook_count,
            "missing_pairs": missing_pairs,
            "bounded_backfill_page_rows": first_page,
            "rows_after_next_page": next_page,
            "delivered_after_next_page": delivered_after_next_page,
            "delivered_in_later_round": later_round,
            "delivered_total": delivered_total,
        }

    def backlog_failure_restart():
        worker(False)
        backlog_markers = [f"backlog-{index}" for index in range(20)]
        backlog_hook = hook("forge", ["ping"], timeout_ms=3000, max_attempts=2)
        for marker in backlog_markers:
            receiver.delay(marker, 0.15)
        receiver.hold(backlog_markers[0])
        for index, marker in enumerate(backlog_markers):
            ping("forge", backlog_hook["id"], marker, f"backlog-event-{index}")
        failed_marker = "backlog-failure"
        receiver.fail(failed_marker)
        failed_hook = hook("other", ["ping"], timeout_ms=2000, max_attempts=1)
        failed_delivery = ping("other", failed_hook["id"], failed_marker, "backlog-failure-1")
        worker(True)

        wait_for("held first backlog send", lambda: receiver.matching(backlog_markers[0]), timeout=15)
        gate = receiver.holds[backlog_markers[0]]
        dead = wait_for("independent failing repository to reach dead_letter", lambda: (
            lambda d: d if d["state"] == "dead_letter" else None
        )(delivery("other", failed_hook["id"], failed_delivery["id"])), timeout=15)
        assert dead["attempts"] == 1, dead
        assert not gate["event"].is_set()
        attempts_while_held = sum(len(receiver.matching(marker)) for marker in backlog_markers)
        assert attempts_while_held == 1, f"bounded serial batch should have one in-flight send, saw {attempts_while_held}"
        held_id = (receiver.matching(backlog_markers[0])[0])["delivery"]
        durable_before_restart = row_state(held_id)
        assert durable_before_restart in ("leased,1", "failed,1"), durable_before_restart
        harness.stop(hard=True)
        gate["event"].set()
        worker(True)

        wait_for("all backlog rows after restart", lambda: all(
            (lambda d: d["state"] == "delivered")(delivery("forge", backlog_hook["id"], row["id"]))
            for row in [ping_delivery_row(backlog_hook["id"], f"backlog-event-{index}")
                        for index in range(20)]
        ), timeout=45)
        attempts = {marker: receiver.attempts(marker) for marker in backlog_markers}
        assert all(1 <= len(values) <= 2 for values in attempts.values()), attempts
        assert all(values[-1] == len(values) for values in attempts.values()), attempts
        assert all(len(receiver.delivery_ids(marker)) == 1 for marker in backlog_markers), attempts
        failed_after = delivery("other", failed_hook["id"], failed_delivery["id"])
        assert failed_after["state"] == "dead_letter" and failed_after["attempts"] == 1, failed_after
        return {
            "backlog_size": len(backlog_markers),
            "attempts_while_first_send_held": attempts_while_held,
            "durable_state_before_hard_restart": durable_before_restart,
            "failure_isolated_dead_letter_attempts": failed_after["attempts"],
            "delivered_after_restart": len(backlog_markers),
            "attempts_per_marker": attempts,
        }

    def ping_delivery_row(hook_id, event_id):
        row = harness.sql(
            "SELECT id::text || ',' || state || ',' || attempts FROM forge_webhook_deliveries "
            f"WHERE webhook_id='{hook_id}' AND event_id='{event_id}'")
        assert row, f"missing delivery row for {event_id}"
        parts = row.split(",")
        return {"id": parts[0], "state": parts[1], "attempts": int(parts[2])}

    def graceful_cancel_restart():
        worker(False)
        cancel_markers = [f"cancel-{index}" for index in range(5)]
        cancel_hook = hook("forge", ["ping"], timeout_ms=5000, max_attempts=3)
        for index, marker in enumerate(cancel_markers):
            ping("forge", cancel_hook["id"], marker, f"cancel-event-{index}")
        gate = receiver.hold(cancel_markers[0])
        worker(True)
        wait_for("cancel case worker send", lambda: receiver.matching(cancel_markers[0]), timeout=15)
        first_id = receiver.matching(cancel_markers[0])[0]["delivery"]
        leased = delivery("forge", cancel_hook["id"], first_id)
        assert leased["state"] == "leased" and leased["attempts"] == 1, leased
        started = time.monotonic()
        harness.stop(hard=False)
        elapsed = round(time.monotonic() - started, 3)
        assert elapsed < 4.0, f"graceful cancellation took {elapsed}s"
        durable = row_state(first_id)
        assert durable == "leased,1", durable
        gate["event"].set()
        worker(True)
        delivered = wait_for("cancelled delivery reclaimed after restart", lambda: (
            lambda d: d if d["state"] == "delivered" else None
        )(delivery("forge", cancel_hook["id"], first_id)), timeout=30)
        assert delivered["attempts"] == 2, delivered
        assert receiver.attempts(cancel_markers[0]) == [1, 2], receiver.attempts(cancel_markers[0])
        assert receiver.delivery_ids(cancel_markers[0]) == {first_id}
        for index, marker in enumerate(cancel_markers[1:], start=1):
            row = ping_delivery_row(cancel_hook["id"], f"cancel-event-{index}")
            wait_for(f"{marker} delivered", lambda row=row: (
                lambda d: d if d["state"] == "delivered" else None
            )(delivery("forge", cancel_hook["id"], row["id"])), timeout=30)
        return {
            "graceful_stop_seconds": elapsed,
            "durable_state_after_cancel": durable,
            "attempts_after_restart": delivered["attempts"],
            "receiver_attempts": receiver.attempts(cancel_markers[0]),
            "same_delivery_id": next(iter(receiver.delivery_ids(cancel_markers[0]))),
        }


    def valid_twelve_second_receiver_is_not_phase_cancelled():
        worker(False)
        slow_hook = hook("forge", ["ping"], timeout_ms=20000, max_attempts=3)
        marker = "valid-12s-receiver"
        receiver.delay(marker, 12.0)
        pending = ping("forge", slow_hook["id"], marker, "valid-12s-1")
        # Delivery may start before readiness returns from worker(True).
        started = time.monotonic()
        worker(True)
        done = wait_for("12 second valid receiver to complete", lambda: (
            lambda d: d if d["state"] == "delivered" else None
        )(delivery("forge", slow_hook["id"], pending["id"])), timeout=25)
        elapsed = round(time.monotonic() - started, 3)
        assert elapsed >= 11.0, elapsed
        assert done["attempts"] == 1, done
        assert receiver.attempts(marker) == [1], receiver.attempts(marker)
        return {"receiver_delay_seconds": 12.0, "hook_timeout_ms": 20000,
                "observed_seconds": elapsed, "attempts": done["attempts"],
                "state": done["state"]}

    def cumulative_batch_over_ten_seconds_completes():
        worker(False)
        batch_hook = hook("forge", ["ping"], timeout_ms=15000, max_attempts=2)
        markers = ["cumulative-a", "cumulative-b"]
        for index, marker in enumerate(markers):
            receiver.delay(marker, 6.0)
            ping("forge", batch_hook["id"], marker, f"cumulative-event-{index}")
        worker(True)
        started = time.monotonic()
        rows = []
        for index, marker in enumerate(markers):
            row = ping_delivery_row(batch_hook["id"], f"cumulative-event-{index}")
            rows.append(wait_for(f"cumulative delivery {marker}", lambda row=row: (
                lambda d: d if d["state"] == "delivered" else None
            )(delivery("forge", batch_hook["id"], row["id"])), timeout=30))
        elapsed = round(time.monotonic() - started, 3)
        assert elapsed >= 11.0, elapsed
        assert all(row["attempts"] == 1 for row in rows), rows
        assert [receiver.attempts(marker) for marker in markers] == [[1], [1]]
        return {"per_send_delay_seconds": 6.0, "observed_batch_seconds": elapsed,
                "attempts": [row["attempts"] for row in rows],
                "states": [row["state"] for row in rows]}

    def sequence_order_preserved_for_due_retry():
        worker(False)
        order_hook = hook("forge", ["ping"], timeout_ms=2000, max_attempts=3)
        first = "sequence-1"
        second = "sequence-2"
        first_row = ping("forge", order_hook["id"], first, "sequence-event-1")
        second_row = ping("forge", order_hook["id"], second, "sequence-event-2")
        harness.sql(
            "UPDATE forge_webhook_deliveries SET state='failed',attempts=1, "
            "next_attempt_unix=extract(epoch FROM clock_timestamp())::bigint "
            f"WHERE id='{first_row['id']}'")
        worker(True)
        wait_for("both sequenced deliveries", lambda: all(
            (lambda d: d["state"] == "delivered")(delivery("forge", order_hook["id"], row["id"]))
            for row in (first_row, second_row)), timeout=20)
        seen = [request["body"].get("zen") for request in receiver.requests
                if request["body"].get("zen") in (first, second)]
        assert seen == [first, second], seen
        return {"old_failed_sequence": 1, "pending_sequence": 2,
                "receiver_order": seen}

    try:
        harness.env["ROOTYARD_OUTBOX_WORKER"] = "false"
        harness.setup()
        case("two_sorted_repositories_early_slow_does_not_starve_later", two_sorted_repositories)
        case("small_backfill_next_page_drains_over_rounds", small_backfill_pages_and_drains_over_rounds)
        case("large_outbox_hook_fanout_keeps_later_repo_live", large_outbox_fanout_keeps_later_repo_live)
        case("large_backlog_failure_and_hard_restart", backlog_failure_restart)
        case("graceful_cancel_leaves_durable_claim", graceful_cancel_restart)
        case("valid_12s_receiver_respects_hook_timeout", valid_twelve_second_receiver_is_not_phase_cancelled)
        case("cumulative_batch_over_10s", cumulative_batch_over_ten_seconds_completes)
        case("due_retry_keeps_sequence_order", sequence_order_preserved_for_due_retry)
        success = True
    except Exception as error:
        print(harness.redact(error), file=sys.stderr)
    finally:
        receiver.close()
        try:
            harness.cleanup()
        except Exception as error:
            cases.append(dict(name="cleanup", status="failed", error=harness.redact(error)))
            success = False
        report["passed"] = success
        if args.keep:
            report["retained_directory"] = str(harness.root)
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
