#!/usr/bin/env python3
"""Issue state-filter keyset contract over real HTTP and isolated PostgreSQL."""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import sys

from forge import ForgeHarness


class StateFilterHarness(ForgeHarness):
    def snapshot(self):
        # Full persisted values include versions, timestamps and allocation counters.
        return tuple(self.sql(f"SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb) FROM {table} t")
                     for table in ("forge_issues", "forge_issue_comments", "forge_issue_counters", "forge_creation_requests"))

    def create_issue(self, path, state="open", token=None):
        issue = self.document(path, 201, token=token, method="POST", body={"title": f"Fixture {state}"})
        if state != issue["state"]:
            issue = self.change(path, issue, state, token)
        return issue

    def change(self, path, issue, state, token=None):
        return self.document(path + f"/{issue['number']}", token=token, method="PATCH",
                             body={"expected_version": issue["version"], "state": state})

    def page(self, path, expected, state=None, after=0, limit=2, more=False, **kwargs):
        query = f"?after={after}&limit={limit}"
        if state is not None:
            query += "&state=" + state
        result = self.document(path + query, **kwargs)
        assert set(result) == {"items", "next_after"}, result
        assert result["items"] == expected, result
        assert result["next_after"] == (expected[-1]["number"] if more else None), result
        if state is not None:
            assert all(issue["state"] == state for issue in result["items"])
        return result

    def fixtures(self):
        # Leading/trailing nonmatches and long gaps catch LIMIT-before-filter bugs.
        states = ["closed"] * 3 + ["open"] + ["closed"] * 4 + ["open"]
        states += ["closed"] * 2 + ["open", "closed", "open", "closed", "open"] + ["closed"] * 3
        self.issues = [self.create_issue(self.basepath, state) for state in states]
        self.commentpath = self.basepath + f"/{self.issues[0]['number']}/comments"
        self.comment = self.document(self.commentpath, 201, method="POST", body={"body": "Unaffected comment list"})
        self.other_issues = [self.create_issue(self.second, state) for state in ("closed", "open")]
        self.bob_issues = [self.create_issue(self.bobpath, state, self.bob) for state in ("open", "closed")]

    def sparse_pagination(self):
        before = self.snapshot()
        for state in ("open", "closed", None):
            expected = [issue for issue in self.issues if state is None or issue["state"] == state]
            cursor = 0
            seen = []
            for offset in range(0, len(expected), 2):
                subset = expected[offset:offset + 2]
                page = self.page(self.basepath, subset, state, cursor, more=offset + 2 < len(expected))
                seen.extend(page["items"])
                cursor = subset[-1]["number"]
            assert seen == expected
            self.page(self.basepath, [], state, cursor)
            self.page(self.basepath, [], state, 9223372036854775807)
            assert self.document(self.basepath + ("?state=" + state if state else "")) == {"items": expected, "next_after": None}
        assert self.snapshot() == before
        return "Sparse open/closed pages filter before limit+1; omitted state retains all Issues and number order"

    def boundaries(self):
        before = self.snapshot()
        for state in ("open", "closed"):
            matches = [issue for issue in self.issues if issue["state"] == state]
            for count in (0, 1, 2, 3):
                after = matches[-count - 1]["number"]
                remaining = matches[-count:] if count else []
                self.page(self.basepath, remaining[:2], state, after, more=count > 2)
            # Both endpoints of the accepted limit interval remain valid.
            self.page(self.basepath, matches[:1], state, limit=1, more=True)
            self.page(self.basepath, matches, state, limit=100)
        assert self.snapshot() == before

    def strict_queries(self):
        before = self.snapshot()
        for query in ("state=", "state", "state=all", "state=Open", "state=CLOSED", "state=%20open", "state=open%20",
                      "state=open&state=open", "state=open&state=closed", "state=closed&state=", "state=open&%73tate=open",
                      "state=open&extra=x", "State=open", "state=open&limit=0", "state=open&limit=101",
                      "state=closed&after=-1", "state=open&after=9223372036854775808", "state=open&after=wat",
                      "state=open&limit=", "state=open&after=", "state=open&limit=1&limit=2", "state=open&after=0&after=1"):
            self.expect(self.basepath + "?" + query, 400, token=self.alice)
        # IssuePage must not accidentally broaden the comment Page extractor.
        for query in ("state=open", "state=closed", "state=", "state=open&limit=1"):
            self.expect(self.commentpath + "?" + query, 400, token=self.alice)
        assert self.document(self.commentpath) == {"items": [self.comment], "next_after": None}
        assert self.snapshot() == before

    def access(self):
        before = self.snapshot()
        for state in ("open", "closed"):
            matches = [issue for issue in self.issues if issue["state"] == state]
            for kwargs in ({"token": self.reader}, {"basic": True}, {"token": self.reader, "basic": True}):
                self.page(self.basepath, matches, state, limit=100, **kwargs)
            path = self.basepath + "?state=" + state
            self.expect(path, 401)
            self.document(path, 404, token=self.bob)
            self.document(self.bobpath + "?state=" + state, 404)
            self.document("/api/repos/alice/missing/issues?state=" + state, 404)
            self.expect(path, 401, token={**self.alice, "username": "bob"}, basic=True)
            self.page(self.second, [i for i in self.other_issues if i["state"] == state], state)
            self.page(self.bobpath, [i for i in self.bob_issues if i["state"] == state], state, token=self.bob)
        for mutation in ("revoked=true", "expires_at=clock_timestamp()-interval '1 second'"):
            token = self.account("create-token", "alice")
            self.sql(f"UPDATE tokens SET {mutation} WHERE id='{token['token_id']}'")
            for state in ("open", "closed"):
                self.document(self.basepath + "?state=" + state, 401, token=token)
        self.sql(f"UPDATE repositories SET state='recovering' WHERE id='{self.repo['id']}'")
        try:
            for state in ("open", "closed"):
                self.document(self.basepath + "?state=" + state, 409)
        finally:
            self.sql(f"UPDATE repositories SET state='ready' WHERE id='{self.repo['id']}'")
        assert self.snapshot() == before

    def authorization_locks(self):
        before = self.snapshot()
        for mutation in ("revoked=true", "expires_at=clock_timestamp()-interval '1 second'"):
            token = self.account("create-token", "alice")
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                with self.held_transaction(f"UPDATE tokens SET {mutation} WHERE id='{token['token_id']}'"):
                    future = executor.submit(self.document, self.basepath + "?state=open", 401, token=token)
                    self.wait_for_lock()
                    assert not future.done()
                future.result()
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            try:
                with self.held_transaction(f"UPDATE repositories SET state='recovering' WHERE id='{self.repo['id']}'"):
                    future = executor.submit(self.document, self.basepath + "?state=closed", 409)
                    self.wait_for_lock()
                    assert not future.done()
                future.result()
            finally:
                self.sql(f"UPDATE repositories SET state='ready' WHERE id='{self.repo['id']}'")
        assert self.snapshot() == before
        return "Filtered reads wait for authorization/repository locks and reject newly revoked, expired or recovering state"

    def live_pagination(self):
        # A separate fixture avoids dependence on another case's mutations/numbers.
        self.document("/api/repos", 201, method="POST", body={"name": "live"})
        path = "/api/repos/alice/live/issues"
        issues = [self.create_issue(path, state) for state in ("closed", "open", "open", "open", "closed", "closed")]
        first = self.page(path, [issues[1], issues[2]], "open", more=True)
        cursor = first["next_after"]
        # A newly matching row behind the cursor and close/reopen of a returned
        # row must not be revisited. Ahead: remove one match and add two matches.
        issues[0] = self.change(path, issues[0], "open")
        issues[1] = self.change(path, issues[1], "closed")
        issues[1] = self.change(path, issues[1], "open")
        issues[3] = self.change(path, issues[3], "closed")
        issues[4] = self.change(path, issues[4], "open")
        issues[5] = self.change(path, issues[5], "open")
        added = self.create_issue(path)
        before = self.snapshot()
        second = self.page(path, issues[4:6], "open", cursor, more=True)
        self.page(path, [added], "open", second["next_after"])
        self.page(path, issues + [added], limit=100)
        self.page(path, [issues[3]], "closed", cursor)
        assert self.snapshot() == before
        return "Ahead-of-cursor changes/new Issues appear; newly matching or reopened earlier numbers are not revisited"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("ROOTYARD_TEST_DATABASE_URL is required")
    harness = StateFilterHarness(args)
    success = False
    try:
        for name in ("setup", "fixtures", "sparse_pagination", "boundaries", "strict_queries", "access", "authorization_locks", "live_pagination"):
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
                      limitations=["Live keyset lists are not snapshots across requests.",
                                   "Small functional fixtures do not establish large-repository performance or an index guarantee."])
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
