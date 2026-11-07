#!/usr/bin/env python3
"""Native repository list pagination against a disposable PostgreSQL schema.

The fixture makes 1001 repositories visible to one actor through real API
creation (one personal, one organization-owned) plus 999 ready catalog rows.
Every assertion below is made through `GET /api/repos` on a running binary;
direct SQL only seeds and mutates catalog fixtures. The default page must stop
at 1000 with a next cursor, not silently truncate, and bounded exhaustive
traversal must return each repository exactly once in keyset order.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import traceback
import urllib.parse
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from e2e import Harness  # noqa: E402


def key(repo):
    return (repo["owner"], repo["name"], repo["id"].lower())


class RepositoryPaginationHarness(Harness):
    def doc(self, path, code, token=None, **kwargs):
        status, body, headers = self.http(path, token=token or self.alice, **kwargs)
        assert status == code, f"{path}: expected {code}, got {status}: {body[:300]!r}"
        return (json.loads(body) if body else None), {k.lower(): v for k, v in headers.items()}

    def page(self, query, token=None):
        body, headers = self.doc("/api/repos?" + query, 200, token=token or self.alice)
        assert isinstance(body, dict) and set(body) == {"items", "next_cursor"}, body
        items = body["items"]
        assert isinstance(items, list) and all({"id", "name", "owner"} <= set(item) for item in items)
        assert headers.get("x-next-cursor") == body["next_cursor"]
        return body, headers

    def legacy(self, query="", token=None):
        body, headers = self.doc("/api/repos" + ("?" + query if query else ""), 200, token=token or self.alice)
        assert isinstance(body, list) and all({"id", "name", "owner"} <= set(item) for item in body)
        return body, headers

    def walk(self, limit, token=None, start=None):
        items, cursor, seen, pages = [], start, set(), 0
        while True:
            query = f"limit={limit}&page=true" + (
                "&cursor=" + urllib.parse.quote(cursor, safe="") if cursor else "")
            body, headers = self.page(query, token)
            batch = body["items"]
            assert len(batch) <= limit, f"page exceeded limit {limit}: {len(batch)}"
            items.extend(batch)
            pages += 1
            assert pages < 100, "cursor did not terminate"
            cursor = body["next_cursor"]
            if cursor is None:
                assert "x-next-cursor" not in headers and "link" not in headers
                break
            assert cursor not in seen, "next cursor repeated"
            seen.add(cursor)
            assert headers["x-next-cursor"] == cursor
            target, rel = headers["link"].rsplit(";", 1)
            assert rel.strip() == 'rel="next"' and target.startswith("<") and target.endswith(">")
            parsed = urllib.parse.urlsplit(target[1:-1])
            assert parsed.path == "/api/repos", parsed.path
            values = urllib.parse.parse_qs(parsed.query)
            assert values["cursor"] == [cursor] and values["limit"] == [str(limit)]
            assert values.get("page") == ["true"]
        return items, pages

    def reject(self, query, token=None):
        status, body, _ = self.http("/api/repos?" + query, token=token or self.alice)
        assert status == 400, f"{query[:80]}: expected 400, got {status}: {body[:200]!r}"

    @staticmethod
    def encode(raw):
        return base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")

    def fixture(self):
        self.setup()
        self.doc("/api/orgs", 201, method="POST", body={"slug": "acme"})
        self.doc("/api/repos", 201, method="POST", body={"owner": "acme", "name": "project"})
        self.doc("/api/repos", 201, method="POST", body={"name": "anchor"})
        for name in ("bob-a", "bob-z"):
            self.doc("/api/repos", 201, token=self.bob, method="POST", body={"name": name})
        owner = self.alice["user_id"]
        inserted = self.sql(
            "INSERT INTO repositories(id,owner_id,name,state) SELECT gen_random_uuid(),'"
            + owner + "','bulk-'||lpad(g::text,4,'0'),'ready' FROM generate_series(0,998) g RETURNING id")
        assert len(inserted.splitlines()) == 999, inserted[-200:]
        self.expected, pages = self.walk(1000)
        assert len(self.expected) == 1001 and pages == 2, (len(self.expected), pages)
        self.expected_keys = {key(repo) for repo in self.expected}
        return {"visible": len(self.expected), "pages_at_limit_1000": pages,
                "repository_set_sha256": hashlib.sha256(
                    "\n".join(sorted(repo["id"] for repo in self.expected)).encode()).hexdigest()}

    def default_boundary(self):
        first, headers = self.legacy()
        assert len(first) == 1000, len(first)
        cursor = headers.get("x-next-cursor")
        assert cursor and "link" in headers
        second, tail_headers = self.legacy("cursor=" + urllib.parse.quote(cursor, safe=""))
        assert len(second) == 1 and "x-next-cursor" not in tail_headers and "link" not in tail_headers
        combined = first + second
        keys = [key(repo) for repo in combined]
        assert len(set(keys)) == len(keys) == 1001
        assert set(keys) == self.expected_keys, "default cursor boundary lost or duplicated rows"
        assert keys == sorted(keys), "default pages are not globally ordered"
        return {"first_page": len(first), "second_page": len(second), "unique": len(set(keys))}

    def bounded_traversal(self):
        items, pages = self.walk(97)
        keys = [key(repo) for repo in items]
        assert pages == 11 and len(keys) == 1001, (pages, len(keys))
        assert len(set(keys)) == 1001 and keys == sorted(keys)
        assert set(keys) == self.expected_keys
        return {"pages": pages, "unique": len(set(keys)), "page_size": 97}

    def cursor_contract(self):
        first, headers = self.page("limit=5&page=true")
        cursor = first["next_cursor"]
        assert cursor and cursor == headers["x-next-cursor"]
        assert cursor.isascii() and all(c.isalnum() or c in "-_" for c in cursor), cursor
        again, _ = self.page("limit=5&page=true&cursor=" + urllib.parse.quote(cursor, safe=""))
        repeat, _ = self.page("limit=5&page=true&cursor=" + urllib.parse.quote(cursor, safe=""))
        assert [repo["id"] for repo in again["items"]] == [repo["id"] for repo in repeat["items"]]
        wider, _ = self.page("limit=17&page=true&cursor=" + urllib.parse.quote(cursor, safe=""))
        assert len(wider["items"]) == 17
        assert [repo["id"] for repo in wider["items"][:5]] == [repo["id"] for repo in again["items"]]
        assert not ({key(repo) for repo in first["items"]} & {key(repo) for repo in wider["items"]})

        scope = "repositories:" + self.alice["user_id"]
        malformed = {
            "empty": "",
            "garbage": "not-base64!",
            "oversized": "a" * 513,
            "wrong_version": self.encode(f"v2:{len(scope)}:{scope}:1:a"),
            "short": self.encode(f"v1:{len(scope)}:{scope}"),
            "long": self.encode(f"v1:{len(scope)}:{scope}:1:a:1:b:1:c:1:d"),
            "utf8_split": self.encode(f"v1:{len(scope)}:{scope}:1:é"),
            "nul_owner": self.encode(
                f"v1:{len(scope)}:{scope}:1:\x00:1:a:36:00000000-0000-0000-0000-000000000001"),
            "invalid_name": self.encode(
                f"v1:{len(scope)}:{scope}:5:alice:3:a/b:36:00000000-0000-0000-0000-000000000001"),
        }
        for label, raw in malformed.items():
            self.reject("limit=1&cursor=" + urllib.parse.quote(raw, safe=""))
        for query in ("limit=0", "limit=1001", "limit=-1", "limit=abc", "limit=1.5", "page=yes", "bogus=1"):
            self.reject(query)
        assert self.http("/api/repos?limit=1")[0] == 401
        assert self.http("/api/repos?limit=1", token={"token": "invalid"})[0] == 401
        return {"malformed_rejected": len(malformed), "limits_rejected": 5, "query_rejected": 2}

    def actor_scope(self):
        alice_first, _ = self.page("limit=1&page=true")
        alice_cursor = alice_first["next_cursor"]
        alice_second, _ = self.page("limit=1&page=true&cursor=" + urllib.parse.quote(alice_cursor, safe=""))
        bob_page, bob_headers = self.page("limit=2&page=true", token=self.bob)
        assert len(bob_page["items"]) == 2 and bob_page["next_cursor"] is None
        assert "x-next-cursor" not in bob_headers and {repo["owner"] for repo in bob_page["items"]} == {"bob"}
        status, _, _ = self.http("/api/repos?limit=1&page=true&cursor="
                                 + urllib.parse.quote(alice_cursor, safe=""), token=self.bob)
        assert status == 400, f"foreign actor cursor accepted: {status}"
        bob_first, _ = self.page("limit=1&page=true", token=self.bob)
        status, _, _ = self.http("/api/repos?limit=1&page=true&cursor="
                                 + urllib.parse.quote(bob_first["next_cursor"], safe=""), token=self.alice)
        assert status == 400, f"foreign actor cursor accepted: {status}"
        reader_page, _ = self.page("limit=1&page=true", token=self.reader)
        assert reader_page["items"][0]["id"] == alice_first["items"][0]["id"]
        reader_next, _ = self.page("limit=1&page=true&cursor="
                                   + urllib.parse.quote(alice_cursor, safe=""), token=self.reader)
        assert reader_next["items"][0]["id"] == alice_second["items"][0]["id"]
        return {"alice_cursor_on_bob": 400, "bob_cursor_on_alice": 400,
                "bob_visible": len(bob_page["items"]), "read_only_scope_shared": True}

    def concurrent_changes(self):
        first, headers = self.page("limit=10&page=true")
        cursor = first["next_cursor"]
        page_one = [key(repo) for repo in first["items"]]
        owner = self.alice["user_id"]
        deleted = self.sql(
            f"DELETE FROM repositories WHERE owner_id='{owner}' AND name='bulk-0500'")
        assert deleted == "DELETE 1", deleted
        early, late = str(uuid.uuid4()), str(uuid.uuid4())
        self.sql(
            "INSERT INTO repositories(id,owner_id,name,state) VALUES "
            f"('{early}','{owner}','bulk-0000x','ready'),('{late}','{owner}','zz-late','ready')")
        resumed, pages = self.walk(37, start=cursor)
        resumed_keys = [key(repo) for repo in resumed]
        assert pages == 27 and len(resumed_keys) == 991, (pages, len(resumed_keys))
        assert not (set(page_one) & set(resumed_keys)), "page overlap after catalog mutation"
        assert all(repo_key[1] not in {"bulk-0500", "bulk-0000x"} for repo_key in resumed_keys)
        assert ("alice", "zz-late", late) in resumed_keys
        combined = page_one + resumed_keys
        wanted = [key(repo) for repo in self.expected if repo["name"] != "bulk-0500"]
        wanted.append(("alice", "zz-late", late))
        assert combined == sorted(combined), "resumed keyset order regressed"
        assert combined == wanted, "mutation traversal lost, replayed or invented rows"
        return {"pages_after_cursor": pages, "unique_after_mutation": len(set(combined)),
                "deleted_absent": True, "early_insert_not_replayed": True, "late_insert_visible": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path, help="Write machine-readable JSON report (no credentials)")
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("ROOTYARD_TEST_DATABASE_URL is required; use a dedicated test database")
    if not Path(args.binary).is_file():
        parser.error("Binary not found: " + args.binary)
    h = RepositoryPaginationHarness(args)
    success = False
    report = {"binary_sha256": hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
              "source_head": subprocess.run(
                  ["git", "-C", str(Path(__file__).resolve().parents[1]), "rev-parse", "HEAD"],
                  stdout=subprocess.PIPE, check=True).stdout.decode().strip()}
    try:
        for name in ("fixture", "default_boundary", "bounded_traversal",
                     "cursor_contract", "actor_scope", "concurrent_changes"):
            h.case(name, getattr(h, name))
        success = True
    except Exception:
        print(h.redact(traceback.format_exc()), file=sys.stderr)
    finally:
        try:
            h.cleanup()
        except Exception as error:
            h.results.append(dict(name="cleanup", status="failed", error=h.redact(error)))
            success = False
        report.update(passed=success, cases=h.results, limitations=[
            "One loopback process and one disposable PostgreSQL schema; not a scalability benchmark.",
            "The cursor is a bounded scope-bound ordering position, not a signed capability or snapshot.",
            "A catalog rewind/restore can move a cursor outside current rows; clients restart at page one.",
            "Mutation coverage proves keyset semantics for inserts/deletes between pages, not serializable reads.",
        ])
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
