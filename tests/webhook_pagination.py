#!/usr/bin/env python3
"""Native issue #70 regression: serialized delivery allocation and lossless cursor paging.

Runs the real Rust service against a disposable PostgreSQL database. Ping events
create deliveries through the HTTP handler; direct SQL only supplies historical
rows with duplicate `sequence` values that the old global `MAX(sequence)+1`
allocator could leave behind. Following `next_cursor` at page sizes 1, 2 and 50
must then return every such delivery ID exactly once in `(sequence, id)` order,
while the legacy numeric `after=N` remains accepted as lossy.

The barrier cases use a real psql transaction that holds the parent
`forge_webhooks` row `FOR UPDATE`. A concurrent ping must wait at the allocator
statement, and after commit it must see the holder's child row and allocate the
next sequence. Rollback must leave no sequence gap. The same fixture also proves
that a different hook is not blocked by the first hook's parent lock.
"""
import argparse
import concurrent.futures
import contextlib
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from webhooks import WebhooksHarness  # noqa: E402


SIGNATURE = "sha256=" + ("0" * 64)


class PaginationHarness(WebhooksHarness):
    def hook(self):
        return self.document(
            self.webhookspath,
            201,
            method="POST",
            body={
                "url": self.receiver.url,
                "secret": self.webhook_secret,
                "events": ["ping"],
                "auto_ci_pin": False,
                "timeout_ms": 3000,
                "max_attempts": 3,
            },
        )

    def ping(self, hook_id, event_id, deliver_now=False):
        return self.document(
            f"{self.webhookspath}/{hook_id}/ping",
            200,
            method="POST",
            body={"zen": f"event {event_id}", "event_id": event_id, "deliver_now": deliver_now},
        )

    def page(self, hook_id, query):
        return self.document(f"{self.webhookspath}/{hook_id}/deliveries?{query}")

    def insert_delivery(self, hook_id, sequence, event_id, delivery_id=None):
        delivery_id = delivery_id or uuid.uuid4()
        tenant, repo = self.alice["user_id"], self.repo["id"]
        self.sql(
            "INSERT INTO forge_webhook_deliveries "
            "(id,webhook_id,tenant_id,repository_id,sequence,event_id,event_type,payload,"
            "request_headers,signature_256,state,attempts,max_attempts,next_attempt_unix) VALUES "
            f"('{delivery_id}','{hook_id}','{tenant}','{repo}',{sequence},'{event_id}','ping',"
            f"'{{}}'::jsonb,'{{}}'::jsonb,'{SIGNATURE}','pending',0,3,0)"
        )
        return str(delivery_id)

    def sequences(self, hook_id):
        raw = self.sql(
            "SELECT string_agg(sequence::text,',' ORDER BY sequence,id) FROM forge_webhook_deliveries "
            f"WHERE webhook_id='{hook_id}'"
        )
        return [] if not raw else [int(value) for value in raw.split(",")]

    def wait_for_allocator_lock(self):
        deadline = time.monotonic() + 5
        query = (
            "SELECT count(*) FROM pg_stat_activity WHERE application_name='rootyard' "
            "AND wait_event_type='Lock' AND query LIKE '%forge_webhooks%FOR UPDATE%'"
        )
        while time.monotonic() < deadline:
            if int(self.sql(query)):
                return
            time.sleep(0.02)
        raise AssertionError("ping never reached the serialized allocator lock")

    @contextlib.contextmanager
    def held_transaction_rollback(self, statement):
        process = subprocess.Popen(
            ["psql", "--dbname", self.db, "-X", "-qAt", "-v", "ON_ERROR_STOP=1"],
            env=self.env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            process.stdin.write("BEGIN; " + statement + "; SELECT 'fixture_locked';\n")
            process.stdin.flush()
            for _ in range(4):
                line = process.stdout.readline().strip()
                if line == "fixture_locked":
                    break
                assert line, "SQL rollback fixture did not initialize"
            else:
                raise AssertionError("SQL rollback fixture did not initialize")
            yield
        finally:
            if process.poll() is None:
                process.stdin.write("ROLLBACK;\n")
                process.stdin.flush()
            process.communicate(timeout=10)
            assert process.returncode == 0

    def allocator_concurrency(self):
        hook = self.hook()
        event_ids = [f"concurrent-{i}" for i in range(60)]

        def ping(event_id):
            return self.ping(hook["id"], event_id)

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            deliveries = list(pool.map(ping, event_ids))
        ids = {item["id"] for item in deliveries}
        assert len(ids) == 60, "concurrent pings returned duplicate delivery ids"
        assert self.sequences(hook["id"]) == list(range(1, 61)), self.sequences(hook["id"])

        first = self.page(hook["id"], "limit=50")
        assert len(first["items"]) == 50
        assert first["next_cursor"]
        assert first["next_after"] == first["items"][-1]["sequence"]
        second = self.page(hook["id"], f"limit=50&cursor={first['next_cursor']}")
        assert len(second["items"]) == 10, "cursor skipped or duplicated the limit+1 probe row"
        combined = first["items"] + second["items"]
        assert len({item["id"] for item in combined}) == 60
        keys = [(item["sequence"], uuid.UUID(item["id"])) for item in combined]
        assert keys == sorted(keys) and keys == sorted(set(keys))
        return {"deliveries": 60, "page1": 50, "page2": 10}

    def walk(self, hook_id, limit):
        """Follow next_cursor to exhaustion; every non-final cursor must advance."""
        pages, items, cursors = [], [], []
        cursor = None
        while True:
            query = f"limit={limit}" + (f"&cursor={cursor}" if cursor else "")
            page = self.page(hook_id, query)
            assert 0 < len(page["items"]) <= limit
            items.extend(page["items"])
            next_cursor = page.get("next_cursor")
            if next_cursor is not None:
                assert next_cursor not in cursors, "cursor repeated"
                last = page["items"][-1]
                assert (last["sequence"], uuid.UUID(last["id"])) > self.cursor_key(next_cursor)
                if cursor is not None:
                    assert self.cursor_key(next_cursor) > self.cursor_key(cursor), "cursor did not advance"
                cursors.append(next_cursor)
            pages.append({"limit": limit, "items": len(page["items"]),
                          "next_cursor": "present" if next_cursor else None,
                          "next_after": page["next_after"]})
            cursor = next_cursor
            if cursor is None:
                break
        return items, pages

    @staticmethod
    def cursor_key(cursor):
        _, _, sequence, item_id = cursor.split(".")
        return int(sequence), uuid.UUID(item_id)

    def cursor_pagination(self):
        hook = self.hook()
        # Historical global MAX allocation could produce these ties.
        sequence_values = [1, 2, 2, 2, 3, 3, 4]
        inserted = [(seq, self.insert_delivery(hook["id"], seq, f"tie-{i}"))
                    for i, seq in enumerate(sequence_values)]
        tied = [item_id for seq, item_id in sorted(inserted, key=lambda item: (item[0], uuid.UUID(item[1])))]
        # Issue #70 acceptance: page sizes 1 and 50 must also walk the complete
        # tied history exactly once, not only page size 2.
        walked = {}
        for limit in (1, 2, 50):
            seen, pages = self.walk(hook["id"], limit)
            assert [item["id"] for item in seen] == tied, (
                f"limit={limit} tied rows were skipped or repeated")
            assert len({item["id"] for item in seen}) == 7
            keys = [(item["sequence"], uuid.UUID(item["id"])) for item in seen]
            assert keys == sorted(keys)
            assert pages[-1]["next_cursor"] is None, f"limit={limit} last page kept a cursor"
            walked[str(limit)] = {"pages": len(pages), "per_page": [p["items"] for p in pages],
                                  "exactly_once": True, "final_next_cursor": None}

        # Legacy after=N is accepted but intentionally lossy for tied values.
        after_two = self.page(hook["id"], "after=2")["items"]
        assert {item["sequence"] for item in after_two} == {3, 4}
        assert all(item["id"] not in tied[:4] for item in after_two)

        self.document(
            f"{self.webhookspath}/{hook['id']}/deliveries?after=1&cursor=v1.{hook['id']}.1.{tied[0]}",
            400,
        )
        other = self.hook()
        self.document(
            f"{self.webhookspath}/{other['id']}/deliveries?cursor=v1.{hook['id']}.1.{tied[0]}",
            400,
        )
        for bad in ("v2.00000000-0000-0000-0000-000000000000.1.00000000-0000-0000-0000-000000000000",
                    "v1.not-a-uuid.1.00000000-0000-0000-0000-000000000000",
                    "v1.00000000-0000-0000-0000-000000000000.0.00000000-0000-0000-0000-000000000000",
                    "v1.00000000-0000-0000-0000-000000000000.1.00000000-0000-0000-0000-000000000000.extra"):
            self.document(f"{self.webhookspath}/{hook['id']}/deliveries?cursor={bad}", 400)
        return {"tied_rows": 7, "walked_page_sizes": walked, "legacy_skipped_ties": True}

    @staticmethod
    def delivery_cursor(hook_id, item):
        return f"v1.{hook_id}.{item['sequence']}.{item['id']}"

    def barrier_commit(self):
        hook = self.hook()
        other = self.hook()
        statement = (
            "SELECT 1 FROM forge_webhooks "
            f"WHERE id='{hook['id']}' FOR UPDATE; "
            "INSERT INTO forge_webhook_deliveries "
            "(id,webhook_id,tenant_id,repository_id,sequence,event_id,event_type,payload,"
            "request_headers,signature_256,state,attempts,max_attempts,next_attempt_unix) VALUES "
            f"('{uuid.uuid4()}','{hook['id']}','{self.alice['user_id']}','{self.repo['id']}',1,"
            f"'holder-event','ping','{{}}'::jsonb,'{{}}'::jsonb,'{SIGNATURE}','pending',0,3,0)"
        )
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            with self.held_transaction(statement):
                waiting = pool.submit(self.ping, hook["id"], "waiter-event")
                self.wait_for_allocator_lock()
                # A different hook must progress while the first parent row is held.
                quick = self.ping(other["id"], "other-hook-event")
                assert quick["sequence"] == 1
                assert not waiting.done(), "enqueue ignored the held parent hook lock"
            result = waiting.result(timeout=10)
        assert result["sequence"] == 2, "READ COMMITTED waiter did not see the committed child row"
        assert self.sequences(hook["id"]) == [1, 2], self.sequences(hook["id"])
        return {"holder_sequence": 1, "waiter_sequence": result["sequence"], "other_sequence": quick["sequence"]}

    def barrier_rollback(self):
        hook = self.hook()
        statement = (
            "SELECT 1 FROM forge_webhooks "
            f"WHERE id='{hook['id']}' FOR UPDATE; "
            "INSERT INTO forge_webhook_deliveries "
            "(id,webhook_id,tenant_id,repository_id,sequence,event_id,event_type,payload,"
            "request_headers,signature_256,state,attempts,max_attempts,next_attempt_unix) VALUES "
            f"('{uuid.uuid4()}','{hook['id']}','{self.alice['user_id']}','{self.repo['id']}',1,"
            f"'rolled-back-holder','ping','{{}}'::jsonb,'{{}}'::jsonb,'{SIGNATURE}','pending',0,3,0)"
        )
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            with self.held_transaction_rollback(statement):
                waiting = pool.submit(self.ping, hook["id"], "after-rollback")
                self.wait_for_allocator_lock()
            result = waiting.result(timeout=10)
        assert result["sequence"] == 1, "rollback leaked a sequence"
        assert self.sequences(hook["id"]) == [1]
        assert int(self.sql(
            "SELECT count(*) FROM forge_webhook_deliveries "
            f"WHERE webhook_id='{hook['id']}' AND event_id='rolled-back-holder'")) == 0
        return {"sequence_after_rollback": result["sequence"]}

    def idempotent_duplicate(self):
        hook = self.hook()

        def duplicate(_):
            return self.ping(hook["id"], "same-event")

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(duplicate, range(8)))
        assert len({item["id"] for item in results}) == 1
        assert int(self.sql(
            "SELECT count(*) FROM forge_webhook_deliveries "
            f"WHERE webhook_id='{hook['id']}' AND event_id='same-event'")) == 1
        following = self.ping(hook["id"], "next-event")
        assert following["sequence"] == 2, "idempotent duplicate consumed a sequence"
        return {"same_id": results[0]["id"], "next_sequence": following["sequence"]}

    def delete_race(self):
        hook = self.hook()
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            with self.held_transaction(f"DELETE FROM forge_webhooks WHERE id='{hook['id']}'"):
                waiting = pool.submit(self.http, f"{self.webhookspath}/{hook['id']}/ping",
                                      token=self.alice, method="POST",
                                      body={"event_id": "deleted-race", "deliver_now": False})
                self.wait_for_allocator_lock()
            status, body, _ = waiting.result(timeout=10)
        assert status == 404, f"deleted hook returned {status}: {body[:200]!r}"
        assert int(self.sql(
            "SELECT count(*) FROM forge_webhook_deliveries "
            f"WHERE event_id='deleted-race'")) == 0
        return {"status": status}

    def explain_index(self):
        hook = self.hook()
        plan = self.sql(
            "SET enable_seqscan=off; EXPLAIN (FORMAT JSON) SELECT COALESCE((SELECT sequence "
            "FROM forge_webhook_deliveries "
            f"WHERE tenant_id='{self.alice['user_id']}' AND repository_id='{self.repo['id']}' "
            f"AND webhook_id='{hook['id']}' ORDER BY sequence DESC LIMIT 1), 0)"
        )
        assert "forge_webhook_deliveries_hook_seq_idx" in plan, plan
        assert "Seq Scan" not in plan, plan
        return {"plan_mentions": "forge_webhook_deliveries_hook_seq_idx"}


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
    harness = PaginationHarness(args)
    report = {
        "issue": 70,
        "binary": args.binary,
        "binary_sha256": hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
        "source_head": subprocess.run(
            ["git", "-C", str(repo_root), "rev-parse", "HEAD"],
            stdout=subprocess.PIPE, check=True,
        ).stdout.decode().strip(),
        "cases": harness.results,
    }
    success = False
    try:
        for name in (
            "setup", "allocator_concurrency", "cursor_pagination", "barrier_commit",
            "barrier_rollback", "idempotent_duplicate", "delete_race", "explain_index",
        ):
            harness.case(name, getattr(harness, name))
        success = True
    except Exception as error:
        print(harness.redact(error), file=sys.stderr)
    finally:
        try:
            harness.cleanup()
        except Exception as error:
            harness.results.append(dict(name="cleanup", status="failed", error=harness.redact(error)))
            success = False
        report.update(passed=success,
                      limitations=[
                          "One host, one disposable PostgreSQL 17 and owned loopback receivers.",
                          "Sequence monotonicity covers retained per-hook history only; operator SQL prune or PITR rollback can reset cursors.",
                          "Concurrency uses bounded threads and real row locks; it is not a throughput benchmark.",
                      ])
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
        return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
