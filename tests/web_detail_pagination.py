#!/usr/bin/env python3
"""Native web detail pagination: issue comments and pull reviews (number keyset).

Implements the real checks for `src/web/detail_pagination.rs`: the issue detail
page (`GET /web/repos/{owner}/{name}/issues/{number}`) and the pull detail page
(`GET /web/repos/{owner}/{name}/pulls/{number}`) render at most 100 child rows and
emit a relative `?cursor=...` next link built from the last rendered per-parent
`number`.

Everything is real:
  * `h.setup()` migrates a disposable schema and starts the real binary.
  * `h.api()` / `h.roundtrip()` create the repository and real Git history.
  * The issue, the feature branch (real `git push`), the pull request, the extra
    comment and the extra review are created through the real HTTP API.
  * Only the historical bulk rows are written with operator SQL, because
    "105 comments/reviews" cannot be produced by a bounded API run in reasonable
    time. SQL seeds are counted by `WITH ... RETURNING ... SELECT count(*)`, so a
    psql command tag can never be mistaken for a row count. The seed must also
    advance `next_comment_number`/`next_review_number` so the HTTP-created row
    lands at 106 without colliding with the seeded keys.

Both `forge_issue_comments` (parent `issue_number`, child `number`) and
`forge_pull_reviews` (parent `pull_number`, child `number`) have no surrogate
`id`, so the child `number` is the only stable ordering key.

The cursor is opaque (`base64url(JSON)` bound to actor/repository/parent/kind).
These cases prove it is a position, not a capability: wrong parent, wrong kind,
malformed, oversized, empty and unknown-query requests are rejected with 400,
and an anonymous request is rejected with 401 instead of silently starting at
page one.
"""
import argparse
import hashlib
import html
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import traceback
import urllib.parse

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from web_sessions import BrowserHarness  # noqa: E402
import native_evidence  # noqa: E402
from scripts.build_native import source_digest  # noqa: E402


PAGE = 100
NEXT_LINK = re.compile(r'<a rel="next" href="([^"]+)">([^<]*)</a>')
COMMENT_NUMBERS = re.compile(r'data-comment-number="(\d+)"')
REVIEW_NUMBERS = re.compile(r'data-review-number="(\d+)"')
COMMENT_MARKER = re.compile(r"page-comment-(\d{4})")
REVIEW_MARKER = re.compile(r"page-review-(\d{4})")


class DetailPaginationHarness(BrowserHarness):
    def api_json(self, path, code, token=None, method="GET", body=None):
        status, raw, _ = self.http(
            path, token=token or self.alice, method=method, body=body
        )
        assert status == code, f"{path}: expected {code}, got {status}: {raw[:300]!r}"
        return json.loads(raw) if raw else None

    def cookie_header(self, cookies=None):
        return super().cookie_header(cookies or self.cookies)

    def web(self, path, cookies=None, extra=None):
        headers = {"Cookie": self.cookie_header(cookies)}
        headers.update(extra or {})
        status, raw, response_headers = self.request(path, headers=headers)
        return status, raw.decode("utf-8", "replace"), dict(response_headers)

    def web_status(self, path, cookies=None):
        cookies = self.cookies if cookies is None else cookies
        headers = {"Cookie": self.cookie_header(cookies)} if cookies else {}
        return self.request(path, headers=headers)[0]

    def walk(self, start, numbers, markers, label):
        """Follow the real `?cursor=` rel=next links for at most 10 pages."""
        path, pages, seen, cursors = start, [], [], set()
        for _ in range(10):
            status, text, _ = self.web(path)
            assert status == 200, (path, status, text[:200])
            pages.append([int(number) for number in numbers.findall(text)])
            seen.extend(markers.findall(text))
            links = NEXT_LINK.findall(text)
            assert len(links) <= 1, (path, links)
            if not links:
                return pages, seen
            href, link_label = links[0]
            assert link_label == label, (path, link_label, label)
            href = html.unescape(href)
            assert href.startswith("?cursor="), href
            assert href not in cursors, "next cursor repeated"
            cursors.add(href)
            path = start + href
        raise AssertionError(f"{start}: pagination did not terminate within 10 pages")

    def seed_comments(self, issue, count):
        tenant = self.tenant
        repo = self.repo["id"]
        author = self.alice["user_id"]
        inserted = self.sql(
            "WITH ins AS (INSERT INTO forge_issue_comments "
            "(tenant_id,repository_id,issue_number,number,author_id,body) "
            f"SELECT '{tenant}','{repo}',{issue},g,'{author}',"
            "'page-comment-' || lpad(g::text,4,'0') "
            f"FROM generate_series(1,{count}) AS g RETURNING 1) "
            "SELECT count(*) FROM ins"
        )
        assert inserted == str(count), f"seeded {inserted} comments, expected {count}"
        self.sql(
            f"UPDATE forge_issues SET next_comment_number={count + 1} "
            f"WHERE tenant_id='{tenant}' AND repository_id='{repo}' AND number={issue}"
        )

    def seed_reviews(self, pull, head_oid, count):
        tenant = self.tenant
        repo = self.repo["id"]
        author = self.alice["user_id"]
        version = self.sql(
            f"SELECT version FROM forge_pulls WHERE tenant_id='{tenant}' "
            f"AND repository_id='{repo}' AND number={pull}"
        )
        inserted = self.sql(
            "WITH ins AS (INSERT INTO forge_pull_reviews "
            "(tenant_id,repository_id,pull_number,number,author_id,state,"
            "commit_oid,pull_version,body) "
            f"SELECT '{tenant}','{repo}',{pull},g,'{author}','commented',"
            f"'{head_oid}',{version},'page-review-' || lpad(g::text,4,'0') "
            f"FROM generate_series(1,{count}) AS g RETURNING 1) "
            "SELECT count(*) FROM ins"
        )
        assert inserted == str(count), f"seeded {inserted} reviews, expected {count}"
        self.sql(
            f"UPDATE forge_pulls SET next_review_number={count + 1} "
            f"WHERE tenant_id='{tenant}' AND repository_id='{repo}' AND number={pull}"
        )

    def fixture(self):
        self.setup()
        self.api()
        self.roundtrip()
        self.tenant = self.sql(
            f"SELECT owner_id FROM repositories WHERE id='{self.repo['id']}'"
        )
        self.schema_versions = self.sql(
            "SELECT string_agg(version::text, ',' ORDER BY version) FROM schema_migrations"
        )
        self.cookies = self.sign_in()[0]

        self.issue = self.api_json(
            "/api/repos/alice/demo/issues",
            201,
            method="POST",
            body={"title": "Pagination comments fixture", "body": "comments fixture"},
        )["number"]

        # Real Git branch and a real HTTP pull request (no seeded PR row).
        self.git("checkout", "-b", "page-feature", cwd=self.work)
        (self.work / "pagination.txt").write_text("pagination fixture\n")
        self.git("add", "pagination.txt", cwd=self.work)
        self.git("commit", "-m", "pagination feature", cwd=self.work)
        self.git("push", "origin", "HEAD:page-feature", cwd=self.work, token=self.alice)
        pull = self.api_json(
            "/api/repos/alice/demo/pulls",
            201,
            method="POST",
            body={
                "title": "Pagination reviews fixture",
                "head_ref": "page-feature",
                "base_ref": "main",
            },
        )
        self.pull, self.head_oid = pull["number"], pull["head_oid"]

        def new_issue(title):
            return self.api_json(
                "/api/repos/alice/demo/issues",
                201,
                method="POST",
                body={"title": title, "body": ""},
            )["number"]

        self.boundary100 = new_issue("Boundary 100 comments fixture")
        self.boundary101 = new_issue("Boundary 101 comments fixture")
        self.empty = new_issue("Empty comments fixture")

        self.seed_comments(self.issue, 105)
        self.seed_comments(self.boundary100, PAGE)
        self.seed_comments(self.boundary101, PAGE + 1)
        self.seed_reviews(self.pull, self.head_oid, 105)

        # Route liveness: one real HTTP comment and one real HTTP review land at
        # 106 because the seeds advanced the per-parent counters.
        self.api_json(
            f"/api/repos/alice/demo/issues/{self.issue}/comments",
            201,
            method="POST",
            body={"body": "page-comment-0106"},
        )
        self.api_json(
            f"/api/repos/alice/demo/pulls/{self.pull}/reviews",
            201,
            method="POST",
            body={"state": "commented", "commit_oid": self.head_oid,
                  "body": "page-review-0106"},
        )
        return {
            "fixtures": {
                "issue_comments_sql_seeded": 105,
                "pull_reviews_sql_seeded": 105,
                "comment_via_http": 1,
                "review_via_http": 1,
                "boundary_comments": {str(PAGE): PAGE, str(PAGE + 1): PAGE + 1},
                "empty_parent_comments": 0,
                "issue_numbers": {"comments": self.issue, "empty": self.empty,
                                  "boundary": [self.boundary100, self.boundary101]},
                "pull_number": self.pull,
                "seed_note": "bulk history is operator SQL, counted via RETURNING; "
                             "the 106th comment/review is written through the API",
            },
            "schema_versions": self.schema_versions,
        }

    def comment_traversal(self):
        path = f"/web/repos/alice/demo/issues/{self.issue}"
        pages, markers = self.walk(path, COMMENT_NUMBERS, COMMENT_MARKER, "Older comments")
        assert pages[0] == list(range(1, PAGE + 1)), pages[0]
        assert pages[1] == list(range(PAGE + 1, 107)), pages[1]
        assert len(pages) == 2, pages
        assert markers == [f"{number:04d}" for number in range(1, 107)], markers[:5]
        assert len(set(markers)) == 106, len(set(markers))
        return {"pages": [len(page) for page in pages], "markers": len(markers),
                "page_size": PAGE}

    def comment_boundaries(self):
        exact = self.walk(
            f"/web/repos/alice/demo/issues/{self.boundary100}",
            COMMENT_NUMBERS, COMMENT_MARKER, "Older comments",
        )
        assert len(exact[0]) == 1 and exact[0][0] == list(range(1, PAGE + 1)), exact[0]
        assert len(exact[1]) == PAGE, len(exact[1])

        over = self.walk(
            f"/web/repos/alice/demo/issues/{self.boundary101}",
            COMMENT_NUMBERS, COMMENT_MARKER, "Older comments",
        )
        assert over[0][0] == list(range(1, PAGE + 1)), over[0][0][:3]
        assert over[0][1] == [PAGE + 1], over[0]
        assert len(over[1]) == PAGE + 1, len(over[1])

        empty_path = f"/web/repos/alice/demo/issues/{self.empty}"
        status, text, _ = self.web(empty_path)
        assert status == 200, (status, text[:200])
        assert not COMMENT_NUMBERS.findall(text)
        assert not COMMENT_MARKER.findall(text)
        assert not NEXT_LINK.findall(text), "empty parent advertised a next page"
        return {"exact_page": PAGE, "probe_next": PAGE + 1, "empty_parent": 0}

    def cursor_rejected(self):
        start = f"/web/repos/alice/demo/issues/{self.boundary101}"
        status, text, _ = self.web(start)
        assert status == 200, (status, text[:200])
        links = NEXT_LINK.findall(text)
        assert len(links) == 1, links
        cursor = urllib.parse.parse_qs(html.unescape(links[0][0])[1:])["cursor"][0]

        def rejected(path):
            status = self.web_status(path)
            assert status == 400, (path, status)
            return status

        other = f"/web/repos/alice/demo/issues/{self.boundary100}"
        assert rejected(f"{other}?cursor={cursor}") == 400
        assert rejected(f"{start}?cursor=not-a-cursor") == 400
        assert rejected(f"{start}?cursor=") == 400
        assert rejected(f"{start}?cursor=" + "A" * 2048) == 400
        assert rejected(f"{start}?after=5") == 400
        assert rejected(f"{start}?limit=2") == 400
        assert self.web_status(other) == 200
        return {"wrong_parent": 400, "malformed": 400, "oversized": 400,
                "echoed_query": 400}

    def review_traversal(self):
        path = f"/web/repos/alice/demo/pulls/{self.pull}"
        pages, markers = self.walk(path, REVIEW_NUMBERS, REVIEW_MARKER, "Older reviews")
        assert pages[0] == list(range(1, PAGE + 1)), pages[0]
        assert pages[1] == list(range(PAGE + 1, 107)), pages[1]
        assert len(pages) == 2, pages
        assert markers == [f"{number:04d}" for number in range(1, 107)], markers[:5]
        assert len(set(markers)) == 106, len(set(markers))

        # A kind-bound cursor cannot be replayed on the other detail list.
        status, text, _ = self.web(f"/web/repos/alice/demo/issues/{self.issue}")
        assert status == 200, (status, text[:200])
        comment_cursor = urllib.parse.parse_qs(
            html.unescape(NEXT_LINK.findall(text)[0][0])[1:]
        )["cursor"][0]
        assert self.web_status(f"{path}?cursor={comment_cursor}") == 400
        return {"pages": [len(page) for page in pages], "markers": len(markers),
                "wrong_kind": 400}

    def anonymous_401(self):
        path = f"/web/repos/alice/demo/issues/{self.issue}"
        assert self.request(path)[0] == 401, "anonymous detail read was not rejected"
        assert self.request(path + "?cursor=abc")[0] == 401
        # A plain browser navigation is redirected to sign-in instead.
        status, _, headers = self.request(
            path, headers={"Accept": "text/html", "Sec-Fetch-Mode": "navigate"}
        )
        assert status == 303, status
        location = self.response_header(headers, "Location") or ""
        assert location.startswith("/web/login?return_to="), location
        return {"plain": 401, "navigation": 303}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("ROOTYARD_TEST_DATABASE_URL is required; use a dedicated test database")
    if not Path(args.binary).is_file():
        parser.error("Binary not found: " + args.binary)

    harness = DetailPaginationHarness(args)
    report = {
        "test": "web_detail_pagination",
        "binary": args.binary,
        "binary_sha256": hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
        "source_head": subprocess.run(
            ["git", "-C", str(Path(__file__).resolve().parents[1]), "rev-parse", "HEAD"],
            stdout=subprocess.PIPE, check=True,
        ).stdout.decode().strip(),
        "schema_versions": None,
        "fixtures": None,
        "cases": harness.results,
    }
    try:
        build = native_evidence.build_record(args.binary)
    except Exception as error:  # a mismatched receipt must not crash the report
        build = {"attested": False, "reason": harness.redact(error)}
    report["build"] = build

    passed = False
    failure_traceback = None
    try:
        assert build.get("attested") is True, "matching build receipt required"
        report["candidate_source_match"] = build.get("source_inputs_sha256") == source_digest()
        assert report["candidate_source_match"], "binary source inputs differ from this candidate"
        harness.case("fixture", harness.fixture)
        report["schema_versions"] = harness.schema_versions
        for name in ("comment_traversal", "comment_boundaries", "cursor_rejected",
                     "review_traversal", "anonymous_401"):
            harness.case(name, getattr(harness, name))
        passed = True
    except Exception as error:
        failure_traceback = harness.redact(traceback.format_exc(limit=20))[-8000:]
        print(harness.redact(error), file=sys.stderr)
        print(failure_traceback, file=sys.stderr)
    finally:
        try:
            harness.cleanup()
        except Exception as error:
            harness.results.append(
                dict(name="cleanup", status="failed", error=harness.redact(error))
            )
            passed = False
        if harness.results and harness.results[0].get("detail"):
            report["fixtures"] = harness.results[0]["detail"].get("fixtures")
        report.update(
            passed=passed,
            cases=harness.results,
            failure_traceback=failure_traceback,
            limitations=[
                "One loopback process and one disposable PostgreSQL schema; not a scalability benchmark.",
                "Bulk history is operator SQL (counted by RETURNING) because 105 rows per list are not produced through HTTP; the 106th row and both parents are created by real HTTP/Git.",
                "The cursor is a scope-bound ordering position, not a signed capability or a snapshot; inserts after the cursor appear later and deletes simply vanish.",
                "Review pagination is exercised on `/web/.../pulls/{number}`; `/web/.../pulls/{number}/reviews` shares the same renderer but is not separately paged here.",
                "The parent/kind and anonymous cases do not establish actor binding or collaborator revocation; those require separate authenticated-actor cases.",
            ],
        )
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
