#!/usr/bin/env python3
"""Private-owner Issue/comment API contract on real isolated PostgreSQL and HTTP."""
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

from e2e import Harness


class ForgeHarness(Harness):
    def document(self, path, code=200, token=None, **kwargs):
        status, body, headers = self.http(path, token=token or self.alice, **kwargs)
        assert status == code, f"{path}: expected {code}, got {status}: {body[:200]!r}"
        assert headers.get("cache-control") == "no-store", headers
        assert "application/json" in headers.get("content-type", "")
        return json.loads(body)

    def setup(self):
        super().setup()
        self.repo = self.document("/api/repos", 201, method="POST", body={"name": "forge"})
        self.other = self.document("/api/repos", 201, method="POST", body={"name": "other"})
        self.bob_repo = self.document("/api/repos", 201, token=self.bob, method="POST", body={"name": "forge"})
        self.basepath = "/api/repos/alice/forge/issues"
        self.second = "/api/repos/alice/other/issues"
        self.bobpath = "/api/repos/bob/forge/issues"

    def migration(self):
        self.stop()
        assert self.sql("SELECT string_agg(version::text,',' ORDER BY version) FROM schema_migrations") == "1,2,3,6,7,8"
        self.cli("migrate")
        self.cli("migrate")
        # Remove only this test's empty Forge slice to reconstruct a real upgrade.
        self.sql("DROP TABLE forge_creation_requests,forge_issue_comments,forge_issues,forge_issue_counters; DELETE FROM schema_migrations WHERE version IN (6,7); CREATE TABLE forge_issue_comments(dummy integer)")
        failed = self.run([self.args.binary, "migrate"], check=False)
        assert failed.returncode != 0
        assert self.sql("SELECT count(*) FROM schema_migrations WHERE version=6") == "0"
        assert self.sql("SELECT count(*) FROM information_schema.tables WHERE table_schema=current_schema() AND table_name IN ('forge_issues','forge_issue_counters')") == "0"
        self.sql("DROP TABLE forge_issue_comments")
        self.cli("migrate")
        self.cli("migrate")
        assert self.sql("SELECT string_agg(version::text,',' ORDER BY version) FROM schema_migrations") == "1,2,3,6,7,8"
        # A conflicting migration007 rolls back its version marker without
        # affecting the already installed Issue/comment schema.
        self.sql("DROP TABLE forge_creation_requests; DELETE FROM schema_migrations WHERE version=7; CREATE TABLE forge_creation_requests(dummy integer)")
        failed = self.run([self.args.binary, "migrate"], check=False)
        assert failed.returncode != 0
        assert self.sql("SELECT count(*) FROM schema_migrations WHERE version=7") == "0"
        assert self.sql("SELECT count(*) FROM information_schema.tables WHERE table_schema=current_schema() AND table_name IN ('forge_issues','forge_issue_counters','forge_issue_comments')") == "3"
        self.sql("DROP TABLE forge_creation_requests")
        self.cli("migrate")
        self.cli("migrate")
        assert self.sql("SELECT string_agg(version::text,',' ORDER BY version) FROM schema_migrations") == "1,2,3,6,7,8"
        assert self.sql("SELECT count(*) FROM repositories") == "3"
        self.start()

    def lifecycle(self):
        self.issue = self.document(self.basepath, 201, method="POST", body={"title": "First issue", "body": "<script>alert(1)</script>\n**untrusted Markdown**"})
        assert self.issue["number"] == 1 and self.issue["state"] == "open" and self.issue["version"] == 1
        assert self.issue["author_id"] == self.alice["user_id"]
        self.issuepath = self.basepath + "/1"
        self.commentpath = self.issuepath + "/comments"
        fetched = self.document(self.issuepath, token=self.reader)
        assert fetched == self.issue
        assert fetched["body"].startswith("<script>")  # Raw text, not rendered executable HTML.
        changed = self.document(self.issuepath, method="PATCH", body={"expected_version": 1, "title": "Changed", "state": "closed", "body": ""})
        assert changed["version"] == 2 and changed["state"] == "closed" and changed["body"] == ""
        self.document(self.issuepath, 409, method="PATCH", body={"expected_version": 1, "title": "Lost update"})
        reopened = self.document(self.issuepath, method="PATCH", body={"expected_version": 2, "state": "open"})
        assert reopened["version"] == 3
        comment = self.document(self.commentpath, 201, method="POST", body={"body": "A comment"})
        assert comment["number"] == 1 and comment["issue_number"] == 1 and comment["author_id"] == self.alice["user_id"]
        assert self.document(self.commentpath + "/1", token=self.reader) == comment
        edited = self.document(self.commentpath + "/1", method="PATCH", body={"expected_version": 1, "body": "Edited"})
        assert edited["version"] == 2 and edited["body"] == "Edited"
        self.document(self.commentpath + "/1", 409, method="PATCH", body={"expected_version": 1, "body": "Stale"})
        # Comments have their own identity/revision, not the Issue's revision.
        assert self.document(self.issuepath)["version"] == 3

    def access(self):
        paths = [self.basepath, self.issuepath, self.commentpath, self.commentpath + "/1"]
        for path in paths:
            self.expect(path, 401)
            self.document(path, 404, token=self.bob)
            self.document(path, token=self.reader)
        for path, method, body in [
            (self.basepath, "POST", {"title": "No"}),
            (self.issuepath, "PATCH", {"expected_version": 3, "title": "No"}),
            (self.commentpath, "POST", {"body": "No"}),
            (self.commentpath + "/1", "PATCH", {"expected_version": 2, "body": "No"}),
        ]:
            self.document(path, 403, token=self.reader, method=method, body=body)
            self.document(path, 404, token=self.bob, method=method, body=body)
        self.document(self.second + "/1", 404)
        self.document(self.second + "/1/comments/1", 404)
        self.document(self.second + "/1/comments", 404, method="POST", body={"body": "Cross repo"})
        assert self.document(self.second)["items"] == []
        other = self.document(self.second, 201, method="POST", body={"title": "Other repository"})
        bob = self.document(self.bobpath, 201, token=self.bob, method="POST", body={"title": "Other tenant"})
        assert other["number"] == bob["number"] == 1
        assert self.document(self.second + "/1")["title"] == "Other repository"
        self.document(self.bobpath, 404)
        self.document(self.basepath, 404, token=self.bob)
        # Basic username must agree with the token's actual principal.
        self.expect(self.basepath, 401, token={**self.alice, "username": "bob"}, basic=True)
        self.document(self.basepath, basic=True)
        for mode in ("revoked", "expired"):
            token = self.account("create-token", "alice")
            sql = "revoked=true" if mode == "revoked" else "expires_at=clock_timestamp()-interval '1 second'"
            self.sql(f"UPDATE tokens SET {sql} WHERE id='{token['token_id']}'")
            for path in paths:
                self.document(path, 401, token=token)
            self.document(self.basepath, 401, token=token, method="POST", body={"title": "No"})

    def boundaries(self):
        for title in ("", " \t", "a\nb", "a\0b", "x" * 257, "界" * 86):
            self.document(self.basepath, 400, method="POST", body={"title": title})
        for body in ("x" * 8193, "a\0b", "a\x01b"):
            self.document(self.basepath, 400, method="POST", body={"title": "bad body", "body": body})
        self.document(self.basepath, 201, method="POST", body={"title": "x" * 256, "body": "x" * 8192})
        for body in ("", " \n\t", "x" * 8193, "a\0b"):
            self.document(self.commentpath, 400, method="POST", body={"body": body})
        self.document(self.commentpath, 201, method="POST", body={"body": "x" * 8192})
        for field in ("author_id", "tenant_id", "repository_id", "state", "number"):
            self.expect(self.basepath, 422, token=self.alice, method="POST", body={"title": "spoof", field: str(uuid.uuid4())})
        self.expect(self.commentpath, 422, token=self.alice, method="POST", body={"body": "spoof", "author_id": self.bob["user_id"]})
        for payload in ({"expected_version": 0, "title": "No"}, {"expected_version": 3}, {"expected_version": 3, "state": "merged"}):
            self.document(self.issuepath, 400, method="PATCH", body=payload)
        self.expect(self.basepath, 413, token=self.alice, method="POST", body={"title": "large", "body": "x" * 20000})
        self.expect(self.basepath, 400, token=self.alice, method="POST", body=b'{"title":', content_type="application/json")
        self.expect(self.basepath, 415, token=self.alice, method="POST", body=b'title')
        for suffix in ("?limit=0", "?limit=101", "?after=-1", "?after=9223372036854775808", "?extra=x", "?limit=1&limit=2"):
            self.expect(self.basepath + suffix, 400, token=self.alice)
            self.expect(self.commentpath + suffix, 400, token=self.alice)
        for path in (self.basepath + "/0", self.basepath + "/-1", self.commentpath + "/0"):
            self.document(path, 400)
        self.document(self.basepath + "/999999", 404)
        self.document(self.basepath + "/999999/comments", 404)
        self.document(self.commentpath + "/999999", 404)
        self.document(self.basepath + "/999999", 404, method="PATCH", body={"expected_version": 1, "title": "missing"})
        self.document(self.commentpath + "/999999", 404, method="PATCH", body={"expected_version": 1, "body": "missing"})

    def concurrency(self):
        before = self.sql("SELECT count(*) FROM forge_issues WHERE repository_id='" + self.repo["id"] + "'")
        def create(i):
            return self.document(self.basepath, 201, method="POST", body={"title": f"Concurrent {i}"})["number"]
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            numbers = list(ex.map(create, range(24)))
        assert len(set(numbers)) == 24
        assert sorted(numbers) == list(range(int(before) + 1, int(before) + 25))
        def comment(i):
            return self.document(self.commentpath, 201, method="POST", body={"body": f"Concurrent {i}"})["number"]
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            numbers = list(ex.map(comment, range(24)))
        assert len(set(numbers)) == 24
        assert sorted(numbers) == list(range(3, 27))
        issue = self.document(self.issuepath)
        def patch(i):
            return self.http(self.issuepath, token=self.alice, method="PATCH", body={"expected_version": issue["version"], "title": f"CAS {i}"})[0]
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            codes = list(ex.map(patch, range(8)))
        assert codes.count(200) == 1 and codes.count(409) == 7, codes
        comment = self.document(self.commentpath + "/1")
        def patch_comment(i):
            return self.http(self.commentpath + "/1", token=self.alice, method="PATCH", body={"expected_version": comment["version"], "body": f"CAS {i}"})[0]
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            codes = list(ex.map(patch_comment, range(8)))
        assert codes.count(200) == 1 and codes.count(409) == 7, codes
        return "24 unique consecutive issue allocations, 24 comment allocations; 1 winner/7 conflicts for each optimistic update"

    def pagination(self):
        for path in (self.basepath, self.commentpath):
            first = self.document(path + "?limit=7")
            assert first["next_after"] == 7
            seen = [i["number"] for i in first["items"]]
            cursor = first["next_after"]
            while cursor is not None:
                page = self.document(path + f"?limit=7&after={cursor}")
                assert len(page["items"]) <= 7
                seen.extend(i["number"] for i in page["items"])
                cursor = page["next_after"]
            assert seen == list(range(1, 27)), seen
            assert self.document(path + "?after=9223372036854775807") == {"items": [], "next_after": None}
            # Mutations do not move rows around a number cursor.
            assert [i["number"] for i in self.document(path + "?after=7&limit=7")["items"]] == list(range(8, 15))

    def database_boundaries(self):
        tenant, repo, wrong = self.alice["user_id"], self.repo["id"], self.bob["user_id"]
        statements = [
            f"INSERT INTO forge_issues(tenant_id,repository_id,number,author_id,title) VALUES('{wrong}','{repo}',900,'{wrong}','cross tenant')",
            f"INSERT INTO forge_issues(tenant_id,repository_id,number,author_id,title) VALUES('{tenant}','{repo}',900,'{wrong}','spoof author')",
            f"INSERT INTO forge_issue_comments(tenant_id,repository_id,issue_number,number,author_id,body) VALUES('{tenant}','{self.other['id']}',2,900,'{tenant}','wrong repo issue')",
            f"INSERT INTO forge_issue_comments(tenant_id,repository_id,issue_number,number,author_id,body) VALUES('{tenant}','{repo}',1,900,'{wrong}','spoof comment author')",
        ]
        for sql in statements:
            result = self.run(["psql", self.db, "-X", "-v", "ON_ERROR_STOP=1", "-c", sql], check=False)
            assert result.returncode != 0
        assert self.sql("SELECT count(*) FROM forge_issues WHERE number=900") == "0"
        assert self.sql("SELECT count(*) FROM forge_issue_comments WHERE number=900") == "0"

    def rollback(self):
        counter = self.sql(f"SELECT next_number FROM forge_issue_counters WHERE repository_id='{self.repo['id']}'")
        self.sql("ALTER TABLE forge_issues ADD CONSTRAINT fixture_failure CHECK (title <> 'injected failure')")
        try:
            self.document(self.basepath, 503, method="POST", body={"title": "injected failure"})
        finally:
            self.sql("ALTER TABLE forge_issues DROP CONSTRAINT fixture_failure")
        assert self.sql(f"SELECT next_number FROM forge_issue_counters WHERE repository_id='{self.repo['id']}'") == counter
        comment_counter = self.sql(f"SELECT next_comment_number FROM forge_issues WHERE repository_id='{self.repo['id']}' AND number=1")
        self.sql("ALTER TABLE forge_issue_comments ADD CONSTRAINT fixture_failure CHECK (body <> 'injected failure')")
        try:
            self.document(self.commentpath, 503, method="POST", body={"body": "injected failure"})
        finally:
            self.sql("ALTER TABLE forge_issue_comments DROP CONSTRAINT fixture_failure")
        assert self.sql(f"SELECT next_comment_number FROM forge_issues WHERE repository_id='{self.repo['id']}' AND number=1") == comment_counter
        self.document(self.basepath, 201, method="POST", body={"title": "after rollback"})
        self.document(self.commentpath, 201, method="POST", body={"body": "after rollback"})

    @contextlib.contextmanager
    def held_transaction(self, sql):
        p = subprocess.Popen(["psql", self.db, "-X", "-qAt", "-v", "ON_ERROR_STOP=1"], env=self.env,
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            p.stdin.write("BEGIN; " + sql + "; SELECT 'fixture_locked';\n")
            p.stdin.flush()
            for _ in range(3):
                line = p.stdout.readline().strip()
                if line == "fixture_locked":
                    break
                assert line, "SQL lock fixture did not initialize"
            else:
                raise AssertionError("SQL lock fixture did not initialize")
            yield p
        finally:
            if p.poll() is None:
                p.stdin.write("COMMIT;\n")
                p.stdin.flush()
            p.communicate(timeout=10)
            assert p.returncode == 0

    def wait_for_lock(self):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            count = self.sql("SELECT count(*) FROM pg_stat_activity WHERE application_name='rootyard' AND wait_event_type='Lock'")
            if int(count):
                return
            time.sleep(.02)
        raise AssertionError("HTTP request never reached the held row lock")

    def permission_races(self):
        for mutation, expected in (("revoked=true", 401), ("read_only=true", 403), ("digest=decode(repeat('00',32),'hex')", 401)):
            token = self.account("create-token", "alice")
            before = self.sql("SELECT count(*) FROM forge_issues")
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                with self.held_transaction(f"UPDATE tokens SET {mutation} WHERE id='{token['token_id']}'"):
                    future = ex.submit(self.http, self.basepath, token=token, method="POST", body={"title": "must not commit"})
                    self.wait_for_lock()
                assert future.result()[0] == expected
            assert self.sql("SELECT count(*) FROM forge_issues") == before
        # Expiration while waiting for the allocation lock must roll back.
        token = self.account("create-token", "alice")
        self.sql(f"UPDATE tokens SET expires_at=clock_timestamp()+interval '1 second' WHERE id='{token['token_id']}'")
        before = self.sql(f"SELECT next_number FROM forge_issue_counters WHERE repository_id='{self.repo['id']}'")
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            with self.held_transaction(f"SELECT next_number FROM forge_issue_counters WHERE repository_id='{self.repo['id']}' FOR UPDATE"):
                future = ex.submit(self.http, self.basepath, token=token, method="POST", body={"title": "expired while blocked"})
                self.wait_for_lock()
                time.sleep(1.1)
            assert future.result()[0] == 401
        assert self.sql(f"SELECT next_number FROM forge_issue_counters WHERE repository_id='{self.repo['id']}'") == before
        # Existing second-phase non-ready repositories must not accept Forge work.
        self.sql(f"UPDATE repositories SET state='recovering' WHERE id='{self.repo['id']}'")
        try:
            self.document(self.basepath, 409)
            self.document(self.basepath, 409, method="POST", body={"title": "not ready"})
        finally:
            self.sql(f"UPDATE repositories SET state='ready' WHERE id='{self.repo['id']}'")
        return "Revocation and read-only changes committed during authorization wait deny writes; expiry during allocation rolls back"

    def restart(self):
        issue = self.document(self.issuepath)
        comments = self.document(self.commentpath)
        self.stop(hard=True)
        self.start()
        assert self.document(self.issuepath) == issue
        assert self.document(self.commentpath) == comments
        self.document(self.issuepath, token=self.reader)
        self.document(self.issuepath, 404, token=self.bob)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("ROOTYARD_TEST_DATABASE_URL is required")
    harness = ForgeHarness(args)
    success = False
    try:
        for name in ("setup", "migration", "lifecycle", "access", "boundaries", "concurrency", "pagination", "database_boundaries", "rollback", "permission_races", "restart"):
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
                      limitations=["Personal owner-only tenancy, not organization/member ACLs.",
                                   "POST creation without Idempotency-Key is not idempotent; inspect uncertain outcomes before retrying.",
                                   "No PR, Review, LFS, CI, Web UI, content rendering, deletion or quota enforcement.",
                                   "Restart and SQL faults do not prove power-loss safety or deployment disaster recovery."])
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
