#!/usr/bin/env python3
"""Durable opt-in creation retries over real HTTP and isolated PostgreSQL."""
import argparse
import concurrent.futures
import hashlib
import http.client
import json
import os
import socket
from pathlib import Path
import sys
import time
import urllib.error

from forge import ForgeHarness


class IdempotencyHarness(ForgeHarness):
    def post(self, path, key, payload, code=201, token=None):
        return self.document(path, code, token=token, method="POST", body=payload,
                             extra_headers={"Idempotency-Key": key})

    def snapshot(self):
        # Includes both allocation counters and stored receipts, not just row counts.
        return tuple(self.sql(f"SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb) FROM {table} t")
                     for table in ("forge_issues", "forge_issue_comments", "forge_issue_counters", "forge_creation_requests"))

    def receipts(self, key):
        return self.sql(f"SELECT count(*) FROM forge_creation_requests WHERE idempotency_key='{key}'")

    def replay(self):
        self.original = self.post(self.basepath, "original", {"title": "Original"})
        self.issuepath = self.basepath + "/" + str(self.original["number"])
        self.commentpath = self.issuepath + "/comments"
        self.comment = self.post(self.commentpath, "original-comment", {"body": "Original comment"})
        before = self.snapshot()
        assert self.post(self.basepath, "original", {"body": "", "title": "Original"}) == self.original
        assert self.post(self.commentpath, "original-comment", {"body": "Original comment"}) == self.comment
        assert self.snapshot() == before
        self.document(self.issuepath, method="PATCH", body={"expected_version": 1, "title": "Edited", "body": "Edited", "state": "closed"})
        self.document(self.commentpath + "/1", method="PATCH", body={"expected_version": 1, "body": "Edited comment"})
        for restart in (False, True):
            if restart:
                self.stop(hard=True)
                self.start()
            before = self.snapshot()
            assert self.post(self.basepath, "original", {"title": "Original"}) == self.original
            assert self.post(self.commentpath, "original-comment", {"body": "Original comment"}) == self.comment
            assert self.snapshot() == before
        return "Issue/comment receipts survive edits and hard service restart; omitted body equals empty body"

    def response_lost(self):
        for index, (path, payload) in enumerate(((self.basepath, {"title": "Unobserved response"}), (self.commentpath, {"body": "Unobserved response"}))):
            key = f"response-lost-{index}"
            body = json.dumps(payload).encode()
            request = (f"POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{self.port}\r\n"
                       f"Authorization: Bearer {self.alice['token']}\r\n"
                       f"Idempotency-Key: {key}\r\nContent-Type: application/json\r\n"
                       f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body
            with socket.create_connection(("127.0.0.1", self.port), timeout=20) as connection:
                connection.sendall(request)
                deadline = time.monotonic() + 10
                while True:
                    saved = self.sql(f"SELECT response FROM forge_creation_requests WHERE idempotency_key='{key}' AND response IS NOT NULL")
                    if saved:
                        break
                    assert time.monotonic() < deadline, "Creation did not commit before response-loss timeout"
                    time.sleep(.02)
                # Deliberately never read any response bytes. PostgreSQL visibility,
                # rather than a sleep, proves the creation committed before close.
            before = self.snapshot()
            assert self.post(path, key, payload) == json.loads(saved)
            assert self.snapshot() == before
        return "Committed issue/comment responses discarded by client; retry returns persisted result without writes"

    def escaped_limits(self):
        body = ('"\\\n\tabcd' * 1024)
        assert len(body.encode()) == 8192
        for index, (path, payload) in enumerate(((self.basepath, {"title": '"' * 256, "body": body}), (self.commentpath, {"body": body}))):
            key = f"escaped-limit-{index}"
            assert len(json.dumps(payload).encode()) < 16 * 1024
            created = self.post(path, key, payload)
            assert created["body"] == body
            before = self.snapshot()
            assert self.post(path, key, payload) == created
            assert self.snapshot() == before

    def conflicts(self):
        other = self.post(self.basepath, "second-issue", {"title": "Second"})
        before = self.snapshot()
        for path, key, body in (
            (self.basepath, "original", {"title": "Different"}),
            (self.basepath, "original", {"title": "Original", "body": "different"}),
            (self.commentpath, "original", {"body": "Original"}),
            (self.basepath, "original-comment", {"title": "Original comment"}),
            (self.commentpath, "original-comment", {"body": "different"}),
            (self.basepath + f"/{other['number']}/comments", "original-comment", {"body": "Original comment"}),
        ):
            self.post(path, key, body, 409)
        assert self.snapshot() == before

    def isolation_and_legacy(self):
        for path, token, title in ((self.second, self.alice, "Other repo"), (self.bobpath, self.bob, "Other owner")):
            created = self.post(path, "original", {"title": title}, token=token)
            assert created["number"] == 1
            assert self.post(path, "original", {"title": title}, token=token) == created
        rotated = self.account("create-token", "alice")
        assert self.post(self.basepath, "original", {"title": "Original"}, token=rotated) == self.original
        for path, body in ((self.basepath, {"title": "No key"}), (self.commentpath, {"body": "No key"})):
            count = self.sql("SELECT count(*) FROM forge_creation_requests")
            first = self.document(path, 201, method="POST", body=body)
            second = self.document(path, 201, method="POST", body=body)
            assert second["number"] == first["number"] + 1
            assert self.sql("SELECT count(*) FROM forge_creation_requests") == count

    def boundaries(self):
        for path, payload in ((self.basepath, {"title": "Header bounds"}), (self.commentpath, {"body": "Header bounds"})):
            before = self.snapshot()
            for key in ("", "x" * 129, "a b", "a,b", "a/b", "a+b", "é"):
                self.post(path, key, payload, 400)
            # urllib dictionaries cannot represent duplicate headers.
            conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=20)
            try:
                data = json.dumps(payload).encode()
                conn.putrequest("POST", path)
                conn.putheader("Authorization", "Bearer " + self.alice["token"])
                conn.putheader("Content-Type", "application/json")
                conn.putheader("Content-Length", str(len(data)))
                conn.putheader("Idempotency-Key", "duplicate")
                conn.putheader("idempotency-key", "duplicate")
                conn.endheaders(data)
                response = conn.getresponse()
                assert response.status == 400, (response.status, response.read())
                response.read()
            finally:
                conn.close()
            assert self.snapshot() == before
        for key in ("a", "x" * 128, "AZaz09._:-"):
            self.post(self.basepath, key, {"title": "Accepted key"})
        before = self.snapshot()
        self.post(self.basepath, "invalid-payload", {"title": ""}, 400)
        self.post(self.commentpath, "invalid-payload", {"body": ""}, 400)
        self.expect(self.basepath, 422, token=self.alice, method="POST", body={"title": "Spoof", "number": 88}, extra_headers={"Idempotency-Key": "invalid-payload"})
        self.expect(self.basepath, 401, method="POST", body={"title": "Anonymous"}, extra_headers={"Idempotency-Key": "anonymous"})
        assert self.snapshot() == before
        self.post(self.basepath, "invalid-payload", {"title": "Retry corrected input"})

    def concurrency(self):
        for index, (path, body) in enumerate(((self.basepath, {"title": "Concurrent"}), (self.commentpath, {"body": "Concurrent"}))):
            key = f"concurrent-{index}"
            table = "forge_issues" if index == 0 else "forge_issue_comments"
            before_count = int(self.sql(f"SELECT count(*) FROM {table}"))
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
                results = list(ex.map(lambda _: self.post(path, key, body), range(16)))
            assert all(result == results[0] for result in results)
            same_number = results[0]["number"]
            assert self.receipts(key) == "1"
            assert int(self.sql(f"SELECT count(*) FROM {table}")) == before_count + 1
            # Distinct semantic requests must have exactly one winning creation.
            key = f"contested-{index}"
            field = "title" if index == 0 else "body"
            def create(i):
                return self.http(path, token=self.alice, method="POST", body={field: f"Candidate {i}"}, extra_headers={"Idempotency-Key": key})
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
                results = list(ex.map(create, range(8)))
            codes = [r[0] for r in results]
            assert codes.count(201) == 1 and codes.count(409) == 7, codes
            assert int(self.sql(f"SELECT count(*) FROM {table}")) == before_count + 2
            winner = json.loads(next(r[1] for r in results if r[0] == 201))
            assert winner["number"] == same_number + 1
            assert self.post(path, key, {field: winner[field]}) == winner
            following = self.document(path, 201, method="POST", body={field: "After race"})
            assert following["number"] == winner["number"] + 1
        return "16 identical concurrent requests create once; 8 competing payloads yield one creation and seven conflicts per resource"

    def rollback(self):
        for index, (path, body, table, field) in enumerate((
            (self.basepath, {"title": "injected failure"}, "forge_issues", "title"),
            (self.commentpath, {"body": "injected failure"}, "forge_issue_comments", "body"),
        )):
            for finalization in (False, True):
                key = f"rollback-{index}-{int(finalization)}"
                target = "forge_creation_requests" if finalization else table
                predicate = f"response IS NULL OR idempotency_key <> '{key}'" if finalization else f"{field} <> 'injected failure'"
                before = self.snapshot()
                self.sql(f"ALTER TABLE {target} ADD CONSTRAINT fixture_failure CHECK ({predicate})")
                try:
                    self.post(path, key, body, 503)
                finally:
                    self.sql(f"ALTER TABLE {target} DROP CONSTRAINT fixture_failure")
                assert self.snapshot() == before
                self.post(path, key, body)
        assert self.sql("SELECT count(*) FROM forge_creation_requests WHERE response IS NULL") == "0"

    def database_contract(self):
        tenant, repo = self.alice["user_id"], self.repo["id"]
        before = self.snapshot()
        prefix = "INSERT INTO forge_creation_requests(tenant_id,repository_id,idempotency_key,request,response) VALUES"
        values = [
            (tenant, repo, "'" + key + "'", "'{}'::jsonb", "'{}'::jsonb")
            for key in ("", "x" * 129, "bad key", "é", "a,b")
        ]
        values += [
            (tenant, repo, "'invalid-sql'", "'[]'::jsonb", "'{}'::jsonb"),
            (tenant, repo, "'invalid-sql'", "'{}'::jsonb", "'null'::jsonb"),
            (tenant, repo, "'invalid-sql'", "'{}'::jsonb", "'[]'::jsonb"),
            (tenant, repo, "'invalid-sql'", "jsonb_build_object('body',repeat('x',65536))", "'{}'::jsonb"),
            (tenant, repo, "'invalid-sql'", "'{}'::jsonb", "jsonb_build_object('body',repeat('x',65536))"),
            (self.bob["user_id"], repo, "'invalid-sql'", "'{}'::jsonb", "'{}'::jsonb"),
        ]
        for owner, repository, key, request, response in values:
            sql = prefix + f"('{owner}','{repository}',{key},{request},{response})"
            assert self.run(["psql", self.db, "-X", "-v", "ON_ERROR_STOP=1", "-c", sql], check=False).returncode != 0
        assert self.snapshot() == before
        # A corrupted committed reservation must fail closed, not allocate again.
        self.sql(self.placeholder_sql("incomplete"))
        try:
            corrupted = self.snapshot()
            self.post(self.basepath, "incomplete", {"title": "Waiting"}, 503)
            assert self.snapshot() == corrupted
        finally:
            self.sql("DELETE FROM forge_creation_requests WHERE idempotency_key='incomplete'")
        assert self.snapshot() == before

    def placeholder_sql(self, key):
        request = json.dumps({"operation": "issue", "title": "Waiting", "body": ""})
        return f"INSERT INTO forge_creation_requests(tenant_id,repository_id,idempotency_key,request) VALUES('{self.alice['user_id']}','{self.repo['id']}','{key}','{request}'::jsonb)"

    def aborted_creator(self):
        before = int(self.sql(f"SELECT next_number FROM forge_issue_counters WHERE repository_id='{self.repo['id']}'"))
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            with self.held_transaction(self.placeholder_sql("aborted")) as transaction:
                future = ex.submit(self.post, self.basepath, "aborted", {"title": "Waiting"})
                self.wait_for_lock()
                assert not future.done()
                transaction.stdin.write("ROLLBACK;\n")
                transaction.stdin.flush()
            created = future.result()
        assert created["number"] == before
        assert self.post(self.basepath, "aborted", {"title": "Waiting"}) == created
        assert self.receipts("aborted") == "1"

    def interrupted_creator(self):
        for index, (path, payload, table, counter, condition) in enumerate((
            (self.basepath, {"title": "Interrupted creator"}, "forge_issue_counters", "next_number", ""),
            (self.commentpath, {"body": "Interrupted creator"}, "forge_issues", "next_comment_number", f" AND number={self.original['number']}"),
        )):
            key = f"interrupted-{index}"
            query = f"SELECT {counter} FROM {table} WHERE repository_id='{self.repo['id']}'{condition}"
            expected_number = int(self.sql(query))
            before = self.snapshot()
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                with self.held_transaction(query + " FOR UPDATE"):
                    future = ex.submit(self.post, path, key, payload)
                    deadline = time.monotonic() + 10
                    while True:
                        # Identify this schema's allocation UPDATE specifically:
                        # reaching it proves the real HTTP transaction reserved its
                        # key before it blocked on our counter/Issue row.
                        blocked = self.sql(f"SELECT a.pid FROM pg_stat_activity a WHERE a.application_name='rootyard' AND a.wait_event_type='Lock' AND a.query LIKE 'UPDATE {table} SET {counter}=%' AND EXISTS (SELECT 1 FROM pg_locks l WHERE l.pid=a.pid AND l.relation='{table}'::regclass)")
                        if blocked:
                            assert len(blocked.splitlines()) == 1, blocked
                            break
                        assert time.monotonic() < deadline, "Creator did not reach allocation lock after reserving key"
                        time.sleep(.02)
                    assert not future.done()
                    self.stop(hard=True)
                    try:
                        future.result(timeout=10)
                    except (http.client.RemoteDisconnected, ConnectionResetError, BrokenPipeError):
                        pass
                    except urllib.error.URLError as error:
                        # Do not hide timeouts, connection refusal, assertions, or
                        # HTTP status failures as a successful crash simulation.
                        assert isinstance(error.reason, (ConnectionResetError, BrokenPipeError)), repr(error.reason)
                    else:
                        raise AssertionError("Killed creator unexpectedly returned a successful response")
                # Release only after the process died and the client disconnected.
                # PostgreSQL may detect its dead client only when its lock wait ends.
                deadline = time.monotonic() + 10
                while self.sql(f"SELECT count(*) FROM pg_stat_activity WHERE pid={int(blocked)}") != "0":
                    assert time.monotonic() < deadline, "Killed creator database transaction did not close"
                    time.sleep(.02)
            assert self.snapshot() == before
            assert self.receipts(key) == "0"
            self.start()
            created = self.post(path, key, payload)
            assert created["number"] == expected_number
            after = self.snapshot()
            assert self.post(path, key, payload) == created
            assert self.snapshot() == after
            assert self.receipts(key) == "1"
        return "Real Issue/comment creators killed after key reservation roll back; restart retries allocate once and replay exactly"

    def permission_races(self):
        payload = {"title": "Original"}
        for token, code in ((self.reader, 403), (self.bob, 404)):
            self.post(self.basepath, "original", payload, code, token)
        for mutation, code in (("revoked=true", 401), ("read_only=true", 403), ("digest=decode(repeat('00',32),'hex')", 401)):
            for key, body in (("original", payload), ("denied-new", {"title": "Denied"})):
                token = self.account("create-token", "alice")
                # Each token digest is unique; do not let this SQL fixture fail
                # on the digest index before the authorization race begins.
                change = mutation
                if mutation.startswith("digest="):
                    digest = hashlib.sha256(token["token_id"].encode()).hexdigest()
                    change = f"digest=decode('{digest}','hex')"
                before = self.snapshot()
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                    with self.held_transaction(f"UPDATE tokens SET {change} WHERE id='{token['token_id']}'"):
                        future = ex.submit(self.post, self.basepath, key, body, code, token)
                        self.wait_for_lock()
                    future.result()
                assert self.snapshot() == before
                self.post(self.basepath, key, body, code, token)
        token = self.account("create-token", "alice")
        self.sql(f"UPDATE tokens SET expires_at=clock_timestamp()+interval '2 seconds' WHERE id='{token['token_id']}'")
        before = self.snapshot()
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            with self.held_transaction(self.placeholder_sql("expires-waiting")) as transaction:
                future = ex.submit(self.post, self.basepath, "expires-waiting", {"title": "Waiting"}, 401, token)
                self.wait_for_lock()
                time.sleep(2.1)
                transaction.stdin.write("ROLLBACK;\n")
                transaction.stdin.flush()
            future.result()
        assert self.snapshot() == before
        self.post(self.basepath, "original", payload, 401, token)
        # Hold a delete of the existing receipt. The unique-key decision waits
        # until rollback makes that original receipt visible again.
        token = self.account("create-token", "alice")
        self.sql(f"UPDATE tokens SET expires_at=clock_timestamp()+interval '2 seconds' WHERE id='{token['token_id']}'")
        before = self.snapshot()
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            with self.held_transaction("DELETE FROM forge_creation_requests WHERE idempotency_key='original' AND repository_id='" + self.repo["id"] + "'") as transaction:
                future = ex.submit(self.post, self.basepath, "original", payload, 401, token)
                self.wait_for_lock()
                deadline = time.monotonic() + 5
                while self.sql(f"SELECT expires_at <= clock_timestamp() FROM tokens WHERE id='{token['token_id']}'") != "t":
                    assert time.monotonic() < deadline, "Token did not expire"
                    time.sleep(.02)
                transaction.stdin.write("ROLLBACK;\n")
                transaction.stdin.flush()
            future.result()
        assert self.snapshot() == before
        self.sql(f"UPDATE repositories SET state='recovering' WHERE id='{self.repo['id']}'")
        try:
            before = self.snapshot()
            self.post(self.basepath, "original", payload, 409)
            self.post(self.commentpath, "original-comment", {"body": "Original comment"}, 409)
            assert self.snapshot() == before
        finally:
            self.sql(f"UPDATE repositories SET state='ready' WHERE id='{self.repo['id']}'")
        assert self.post(self.basepath, "original", payload) == self.original


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("ROOTYARD_TEST_DATABASE_URL is required")
    harness = IdempotencyHarness(args)
    success = False
    try:
        for name in ("setup", "replay", "response_lost", "escaped_limits", "conflicts", "isolation_and_legacy", "boundaries", "concurrency", "rollback", "database_contract", "aborted_creator", "interrupted_creator", "permission_races"):
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
        report = dict(passed=success, cases=harness.results,
                      binary_sha256=hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
                      limitations=["PostgreSQL fixtures model aborted creators and transaction failures; no power-loss guarantee.",
                                   "Creation without Idempotency-Key remains non-idempotent."])
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
