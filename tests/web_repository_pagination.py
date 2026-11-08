#!/usr/bin/env python3
"""Browser repository-discovery pagination against the REAL binary.

`GET /web/repos` must return the complete authorised repository list in two
bounded pages of 100/6 here, using an opaque actor-bound cursor. Every request
below goes through the actual middleware, browser-session exchange and REST
repository-creation API on a loopback server. Direct SQL only seeds catalog
fixtures and membership rows; it never stands in for an HTTP assertion.

Fixture (documented operator shortcut, not a stress benchmark):
  * 105 `ready` repository rows are bulk-seeded in one explicit SQL statement
    with `gen_random_uuid()` and an asserted `SELECT count(*) = 105`.
  * The 106th repository is created through the real `POST /api/repos` API.
  * The bulk rows deliberately have no Git working directory: discovery reads
    only catalog metadata, so per-repository provisioning is not needed and is
    not claimed.

Preconditions: `ROOTYARD_TEST_DATABASE_URL` and a binary built by
`scripts/build_native.py`. The receipt must exist, its `binary_sha256` must
match the executed file (checked by `native_evidence.build_record`), and its
`source_inputs_sha256` must equal the CURRENT `build_native.source_digest()`.
No Cargo build, native harness or fixture is run by this test.
"""
import argparse
import base64
import hashlib
import html
import http.client
import json
import os
import re
import subprocess
import sys
import traceback
import urllib.parse
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from e2e import Harness  # noqa: E402
import native_evidence  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from build_native import source_digest  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
LIMIT = 100


def quote(value):
    return "'" + str(value).replace("'", "''") + "'"


def repo_row(h, owner, name):
    return h.sql(
        "SELECT r.id,r.owner_id FROM repositories r JOIN namespaces ns ON ns.id=r.owner_id "
        f"WHERE ns.slug={quote(owner)} AND r.name={quote(name)}"
    )


def seed_restricted_token(h, token, grants=()):
    """No public restricted-PAT issuer exists; mark an issued token by SQL."""
    h.sql(f"UPDATE tokens SET is_restricted=true WHERE id={quote(token['token_id'])}")
    for repository_id, action in grants:
        h.sql(
            "INSERT INTO token_repository_scopes(token_id,repository_id,action) "
            f"VALUES ({quote(token['token_id'])},{quote(repository_id)},{quote(action)})"
        )
    h.sql(f"UPDATE tokens SET scope_version=scope_version+1 WHERE id={quote(token['token_id'])}")


class WebListingHarness(Harness):
    def request(self, path, method="GET", body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=20)
        conn.request(method, path, body=body, headers=headers or {})
        response = conn.getresponse()
        result = (response.status, response.read(), response.getheaders())
        conn.close()
        return result

    @staticmethod
    def header(headers, name):
        for key, value in headers:
            if key.lower() == name.lower():
                return value
        return None

    @staticmethod
    def cookies(headers):
        out = {}
        for key, value in headers:
            if key.lower() == "set-cookie":
                name, first = value.split(";", 1)[0].split("=", 1)
                out[name] = first
        return out

    @staticmethod
    def cookie_header(jar):
        return "; ".join(f"{k}={v}" for k, v in jar.items())

    def login(self, token=None, username="alice", return_to=None):
        fields = {"username": username, "token": token or self.alice["token"]}
        if return_to is not None:
            fields["return_to"] = return_to
        return self.request(
            "/web/login",
            "POST",
            urllib.parse.urlencode(fields),
            {"Content-Type": "application/x-www-form-urlencoded", "Origin": self.base},
        )

    def sign_in(self, token=None, username="alice"):
        status, body, headers = self.login(token=token, username=username)
        assert status == 303, (status, body[:300])
        jar = self.cookies(headers)
        assert jar.get("rootyard_session", "").startswith("ryt_"), jar
        assert jar.get("rootyard_csrf"), jar
        self.secrets.extend(jar.values())
        return jar

    def get(self, path, jar=None, bearer=None, navigate=False, accept_html=False):
        headers = {}
        if jar:
            headers["Cookie"] = self.cookie_header(jar)
        if bearer:
            headers["Authorization"] = "Bearer " + bearer
        if navigate:
            headers["Accept"] = "text/html"
            headers["Sec-Fetch-Mode"] = "navigate"
        elif accept_html:
            headers["Accept"] = "text/html"
        return self.request(path, headers=headers)

    @staticmethod
    def links(body):
        page = body.decode("utf-8", "strict")
        rows = re.findall(r'<li><a href="/web/repos/([^/"]+)/([^"]+)">', page)
        return [(html.unescape(owner), html.unescape(name)) for owner, name in rows]

    @staticmethod
    def next_href(body):
        page = body.decode("utf-8", "strict")
        found = re.findall(r'<a rel="next" href="([^"]+)">', page)
        assert len(found) <= 1, found
        return found[0] if found else None

    def page(self, jar, href=None):
        path = "/web/repos" + (href or "")
        status, body, _ = self.get(path, jar=jar)
        assert status == 200, (status, body[:300])
        return self.links(body), self.next_href(body), body

    def fixture(self):
        self.setup()
        owner = self.alice["user_id"]
        inserted = self.sql(
            "WITH inserted AS (INSERT INTO repositories(id,owner_id,name,state) "
            f"SELECT gen_random_uuid(),{quote(owner)},'bulk-'||lpad(g::text,3,'0'),'ready' "
            "FROM generate_series(0,104) g RETURNING id) SELECT count(*) FROM inserted"
        )
        assert inserted == "105", inserted
        assert self.sql(
            "SELECT count(*) FROM repositories r JOIN namespaces ns ON ns.id=r.owner_id "
            f"WHERE r.state='ready' AND ns.user_id={quote(owner)}"
        ) == "105"
        api = json.loads(self.expect("/api/repos", 201, method="POST", token=self.alice,
                                     body={"name": "demo"}))
        assert api["state"] == "ready", api
        assert self.sql(
            "SELECT count(*) FROM repositories r JOIN namespaces ns ON ns.id=r.owner_id "
            f"WHERE ns.slug='alice'"
        ) == "106"
        self.demo_id, self.demo_tenant = repo_row(self, "alice", "demo").split("|")
        return {"bulk_rows": 105, "api_created": 1, "visible": 106}

    def two_page_traversal(self):
        jar = self.sign_in()
        first, href, body = self.page(jar)
        assert len(first) == LIMIT, len(first)
        assert href and href.startswith("?cursor="), href
        assert "://" not in href and href.startswith("?"), "next link must be relative"
        parsed = urllib.parse.urlsplit(href)
        cursor = urllib.parse.parse_qs(parsed.query)["cursor"][0]
        assert cursor.isascii() and all(c in "-_" or c.isalnum() for c in cursor), cursor
        second, tail, tail_body = self.page(jar, href)
        assert len(second) == 6, len(second)
        assert tail is None, tail
        assert self.next_href(tail_body) is None
        combined = first + second
        assert len(combined) == 106, len(combined)
        assert len(set(combined)) == 106, "duplicate repository link across pages"
        expected = {("alice", "bulk-%03d" % i) for i in range(105)} | {("alice", "demo")}
        assert set(combined) == expected, (set(expected) - set(combined), set(combined) - set(expected))
        assert combined == sorted(combined), "pages are not globally keyset-ordered"
        assert b"alice/demo" not in body and b"alice/bulk-099" in body
        assert b"alice/demo" in tail_body and b"alice/bulk-000" not in tail_body
        return {"first_page": len(first), "second_page": len(second),
                "unique": len(set(combined)), "next_relative": href.startswith("?cursor=")}

    @staticmethod
    def encode(raw):
        return base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")

    @staticmethod
    def field(value):
        return f":{len(value)}:{value}"

    def cursor_contract(self):
        jar = self.sign_in()
        _, href, _ = self.page(jar)
        cursor = urllib.parse.parse_qs(urllib.parse.urlsplit(href).query)["cursor"][0]
        alice = str(uuid.UUID(self.alice["user_id"]))
        bob_id = str(uuid.UUID(self.bob["user_id"]))
        scope = f"web-repos:discover:v1:all:{alice}"
        bob_scope = f"web-repos:discover:v1:all:{bob_id}"
        restricted_scope = f"web-repos:discover:v1:restricted:{alice}"
        good = ["alice", "bulk-000", "00000000-0000-0000-0000-000000000001"]

        def raw(prefix, scope_value, fields):
            return prefix + self.field(scope_value) + "".join(self.field(f) for f in fields)

        malformed = {
            "empty": "",
            "garbage": "not-base64!",
            "oversized": "a" * 513,
            "wrong_version": self.encode(raw("v2", scope, good)),
            "short": self.encode(raw("v1", scope, good[:2])),
            "long": self.encode(raw("v1", scope, good + ["extra"])),
            "bad_uuid": self.encode(raw("v1", scope, ["alice", "bulk-000", "not-a-uuid"])),
            "bad_slug": self.encode(raw("v1", scope, ["alice/x", "bulk-000", good[2]])),
            "bad_name": self.encode(raw("v1", scope, ["alice", "bulk/000", good[2]])),
            "foreign_actor": self.encode(raw("v1", bob_scope, good)),
            "foreign_audience": self.encode(raw("v1", restricted_scope, good)),
        }
        for label, value in malformed.items():
            status, body, _ = self.get("/web/repos?cursor=" + urllib.parse.quote(value, safe=""), jar=jar)
            assert status == 400, (label, status, body[:200])
        for query in ("bogus=1", "limit=100", f"cursor={urllib.parse.quote(cursor, safe='')}&extra=1"):
            status, body, _ = self.get("/web/repos?" + query, jar=jar)
            assert status == 400, (query, status, body[:200])
        # The valid cursor continues the same list (not a silent page-one fallback).
        resumed, _, _ = self.page(jar, "?cursor=" + urllib.parse.quote(cursor, safe=""))
        assert resumed and ("alice", "bulk-099") not in resumed
        return {"malformed_rejected": len(malformed), "unknown_query_rejected": 3,
                "valid_cursor_resumes": bool(resumed)}

    def actor_binding(self):
        # Bob really can read the same repository, so a rejected cursor is the
        # actor binding, not a missing permission.
        self.sql(
            "INSERT INTO repository_collaborators(repository_id,tenant_id,user_id,role) "
            f"VALUES({quote(self.demo_id)},{quote(self.demo_tenant)},{quote(self.bob['user_id'])},'read')"
        )
        bob = self.sign_in(token=self.bob["token"], username="bob")
        bob_rows, bob_next, bob_body = self.page(bob)
        assert bob_rows == [("alice", "demo")], bob_rows
        assert bob_next is None
        assert self.get("/web/repos/alice/demo", jar=bob)[0] == 200
        alice = self.sign_in()
        alice_rows, alice_next, _ = self.page(alice)
        assert len(alice_rows) == LIMIT and alice_next
        cursor = urllib.parse.parse_qs(urllib.parse.urlsplit(alice_next).query)["cursor"][0]
        status, body, _ = self.get("/web/repos?cursor=" + urllib.parse.quote(cursor, safe=""), jar=bob)
        assert status == 400, (status, body[:200])
        return {"bob_sees": bob_rows, "alice_cursor_on_bob": status,
                "bob_repo_read": 200}

    def current_membership(self):
        self.sql(
            "INSERT INTO repository_collaborators(repository_id,tenant_id,user_id,role) "
            f"VALUES({quote(self.demo_id)},{quote(self.demo_tenant)},{quote(self.bob['user_id'])},'read') "
            "ON CONFLICT DO NOTHING"
        )
        bob = self.sign_in(token=self.bob["token"], username="bob")
        rows, _, body = self.page(bob)
        assert ("alice", "demo") in rows and b"alice/demo" in body
        assert self.get("/web/repos/alice/demo", jar=bob)[0] == 200
        self.sql(
            "DELETE FROM repository_collaborators WHERE repository_id="
            f"{quote(self.demo_id)} AND user_id={quote(self.bob['user_id'])}"
        )
        assert self.get("/web/repos/alice/demo", jar=bob)[0] == 404
        rows, _, body = self.page(bob)
        assert ("alice", "demo") not in rows and b"alice/demo" not in body
        return {"before": 200, "after_revoke": 404, "listing_invisible": True}

    def read_only(self):
        reader = self.sign_in(token=self.reader["token"], username="alice")
        rows, _, body = self.page(reader)
        assert len(rows) == 106 and b"alice/demo" in body, len(rows)
        status, bearer_body, _ = self.get("/web/repos", bearer=self.reader["token"])
        assert status == 200 and b"alice/demo" in bearer_body
        return {"browser_rows": len(rows), "bearer_status": status}

    def restricted_token(self):
        scoped = self.account("create-token", "alice")
        seed_restricted_token(self, scoped, [(self.demo_id, "repo_read"),
                                             (self.demo_id, "contents_read")])
        status, body, _ = self.get("/web/repos", bearer=scoped["token"])
        assert status == 200, (status, body[:300])
        rows = self.links(body)
        assert rows == [("alice", "demo")], rows
        assert b"bulk-" not in body and b"api-created" not in body

        empty = self.account("create-token", "alice")
        seed_restricted_token(self, empty)
        status, empty_body, _ = self.get("/web/repos", bearer=empty["token"])
        assert status == 200, (status, empty_body[:300])
        assert self.links(empty_body) == [], self.links(empty_body)
        assert b"No repositories are available" in empty_body
        api_status, api_body, _ = self.http("/api/repos", token=empty)
        assert api_status == 200 and json.loads(api_body) == [], (api_status, api_body[:200])

        # A restricted parent still cannot open a browser child session. This
        # is the pre-existing contract and is not changed by listing work.
        login_status, login_body, login_headers = self.login(token=scoped["token"], username="alice")
        assert login_status == 403, (login_status, login_body[:300])
        assert not self.cookies(login_headers).get("rootyard_session"), login_headers
        return {"granted_rows": rows, "empty_web": 200, "empty_api": api_status,
                "restricted_login": login_status}

    def anonymous_contract(self):
        # Source contract in src/web/session.rs: a non-navigation request keeps
        # the handler's 401; a browser navigation is redirected with 303 to
        # /web/login. No 302 is produced on this route.
        status, body, _ = self.get("/web/repos")
        assert status == 401, (status, body[:200])
        status, body, headers = self.get("/web/repos", navigate=True)
        assert status == 303, (status, body[:200])
        assert self.header(headers, "Location").startswith("/web/login?return_to=")
        status, body, _ = self.get("/web/repos", accept_html=True)
        assert status == 303, (status, body[:200])
        assert self.get("/web/login")[0] == 200
        return {"plain": 401, "navigate": 303, "login_page": 200}


def write_report(path, report):
    if path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("ROOTYARD_TEST_DATABASE_URL is required")
    if not Path(args.binary).is_file():
        parser.error("Binary not found: " + args.binary)
    if args.report:
        os.environ["ROOTYARD_TEST_EVIDENCE_DIR"] = str(args.report.parent / (args.report.stem + "-evidence"))

    current_digest = source_digest()
    source_head = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"],
                                 stdout=subprocess.PIPE, check=True).stdout.decode().strip()
    try:
        build = native_evidence.build_record(args.binary)
    except Exception as error:  # noqa: BLE001 - receipt mismatch must still be reported
        build = {"attested": False, "reason": str(error)}
    report = {
        "backend": "native",
        "binary": args.binary,
        "binary_sha256": hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
        "source_head": source_head,
        "source_digest": current_digest,
        "build": build,
        "passed": False,
        "cases": [],
        "limitations": [
            "One loopback process and one disposable PostgreSQL schema; this is not a scalability benchmark.",
            "The 105-row fixture is an explicit operator bulk seed; those rows intentionally have no Git repository on disk.",
            "The cursor is a bounded scope-bound position, not a snapshot or signed capability.",
            "Restricted tokens are seeded through SQL because no public restricted-PAT issuer is released.",
            "No Cargo build, native acceptance harness or root fixture was run by this test.",
        ],
    }
    if not build.get("attested"):
        report["error"] = "missing or unattested build receipt"
        write_report(args.report, report)
        return 1
    if build.get("source_inputs_sha256") != current_digest:
        report["error"] = "build receipt source_inputs_sha256 does not match current source"
        write_report(args.report, report)
        return 1

    harness = WebListingHarness(args)
    success = False
    try:
        for name in ("fixture", "two_page_traversal", "cursor_contract", "actor_binding",
                     "current_membership", "read_only", "restricted_token", "anonymous_contract"):
            harness.case(name, getattr(harness, name))
        success = True
    except Exception:
        print(harness.redact(traceback.format_exc()), file=sys.stderr)
    finally:
        try:
            harness.cleanup()
        except Exception as error:  # noqa: BLE001
            harness.results.append({"name": "cleanup", "status": "failed", "error": harness.redact(error)})
            success = False
        report.update(passed=success, cases=harness.results)
        write_report(args.report, report)
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
