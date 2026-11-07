#!/usr/bin/env python3
"""Native organization member/team list pagination against disposable PostgreSQL.

Every assertion runs `GET /api/orgs/{slug}/{members|teams}` on a real binary.
The organization, the owner membership and the read-only token are created
through the real API. Only metadata fixtures are seeded with SQL: 100 extra
`users` rows plus their `read` memberships (the owner's admin membership comes
from the API) and 101 `organization_teams` rows. SQL never grants a role to a
principal that the API did not authenticate, and every seeded insert is
verified with `WITH ... RETURNING ... SELECT count(*)` so a psql command tag
cannot be mistaken for a row count.

The default page keeps the historical `{"items":...,"truncated":...}` envelope
and adds `next_cursor`; cursors are binding positions, not capabilities.
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


def norm(value):
    return str(uuid.UUID(str(value))).lower()


class OrganizationPaginationHarness(Harness):
    def doc(self, path, code=200, token=None, method="GET", body=None):
        status, raw, headers = self.http(path, token=token or self.alice, method=method, body=body)
        assert status == code, f"{path}: expected {code}, got {status}: {raw[:300]!r}"
        return (json.loads(raw) if raw else None), {k.lower(): v for k, v in headers.items()}

    def page(self, org, kind, query="", token=None):
        body, headers = self.doc(
            f"/api/orgs/{org}/{kind}" + ("?" + query if query else ""), token=token
        )
        assert isinstance(body, dict) and set(body) == {"items", "next_cursor", "truncated"}, body
        assert isinstance(body["items"], list) and isinstance(body["truncated"], bool)
        required = {"username", "role", "version"} if kind == "members" else {
            "id", "slug", "name", "role", "version"}
        assert all(required <= set(item) for item in body["items"]), body["items"][:2]
        assert headers.get("x-next-cursor") == body["next_cursor"]
        if body["next_cursor"] is None:
            assert "x-next-cursor" not in headers and "link" not in headers
        return body, headers

    def walk(self, org, kind, limit, token=None, start=None):
        items, cursor, seen_cursors, pages = [], start, set(), 0
        key = (lambda item: item["username"]) if kind == "members" else (lambda item: (item["slug"], item["id"]))
        while True:
            query = f"limit={limit}" + (
                "&cursor=" + urllib.parse.quote(cursor, safe="") if cursor else "")
            body, headers = self.page(org, kind, query, token=token)
            batch = body["items"]
            assert len(batch) <= limit, f"page exceeded limit {limit}: {len(batch)}"
            assert body["truncated"] == (body["next_cursor"] is not None)
            items.extend(batch)
            pages += 1
            assert pages < 100, "cursor did not terminate"
            cursor = body["next_cursor"]
            if cursor is None:
                assert cursor not in seen_cursors
                break
            assert cursor not in seen_cursors, "next cursor repeated"
            seen_cursors.add(cursor)
            target, rel = headers["link"].rsplit(";", 1)
            assert rel.strip() == 'rel="next"' and target.startswith("<") and target.endswith(">")
            parsed = urllib.parse.urlsplit(target[1:-1])
            assert parsed.path == f"/api/orgs/{org}/{kind}", parsed.path
            values = urllib.parse.parse_qs(parsed.query)
            assert values["cursor"] == [cursor] and values["limit"] == [str(limit)], values
        keys = [key(item) for item in items]
        assert keys == sorted(keys), f"{kind} pages are not globally ordered"
        return items, pages

    def reject(self, org, kind, query, token=None):
        status, raw, _ = self.http(f"/api/orgs/{org}/{kind}?" + query, token=token or self.alice)
        assert status == 400, f"{kind}?{query[:100]}: expected 400, got {status}: {raw[:200]!r}"

    @staticmethod
    def encode(raw):
        return base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")

    def scope(self, org, kind, actor=None):
        return f"organization-{kind}:{norm(actor or self.alice['user_id'])}:{norm(org['id'])}"

    def fixture(self):
        self.setup()
        acme, _ = self.doc("/api/orgs", 201, method="POST", body={"slug": "acme"})
        self.acme = acme
        seeded_users = self.sql(
            "WITH inserted_users AS ("
            "INSERT INTO users(id,username) "
            "SELECT gen_random_uuid(),'member-'||lpad(g::text,3,'0') FROM generate_series(1,100) g "
            "RETURNING id), inserted_members AS ("
            "INSERT INTO organization_memberships(organization_id,user_id,role) "
            f"SELECT '{norm(acme['id'])}',id,'read' FROM inserted_users RETURNING user_id) "
            "SELECT count(*) FROM inserted_members")
        assert seeded_users == "100", seeded_users
        seeded_teams = self.sql(
            "WITH inserted AS ("
            "INSERT INTO organization_teams(id,organization_id,slug,name,role) "
            "SELECT gen_random_uuid(),"
            f"'{norm(acme['id'])}','team-'||lpad(g::text,3,'0'),'Team '||g,'read' "
            "FROM generate_series(1,101) g RETURNING id) "
            "SELECT count(*) FROM inserted")
        assert seeded_teams == "101", seeded_teams
        members = self.sql(
            f"SELECT count(*) FROM organization_memberships WHERE organization_id='{norm(acme['id'])}'")
        teams = self.sql(
            f"SELECT count(*) FROM organization_teams WHERE organization_id='{norm(acme['id'])}'")
        assert (members, teams) == ("101", "101"), (members, teams)
        self.expected_members = sorted(["alice"] + [f"member-{i:03d}" for i in range(1, 101)])
        self.expected_teams = [f"team-{i:03d}" for i in range(1, 102)]
        return {"api_created": ["organization:acme", "owner admin membership"],
                "sql_seeded_users_with_read_memberships": int(seeded_users),
                "sql_seeded_teams": int(seeded_teams),
                "members_total": int(members), "teams_total": int(teams)}

    def default_boundary(self):
        body, headers = self.page("acme", "members")
        assert len(body["items"]) == 100 and body["truncated"] is True, (len(body["items"]), body["truncated"])
        cursor = body["next_cursor"]
        assert cursor and headers["x-next-cursor"] == cursor
        target, rel = headers["link"].rsplit(";", 1)
        parsed = urllib.parse.urlsplit(target[1:-1])
        values = urllib.parse.parse_qs(parsed.query)
        assert rel.strip() == 'rel="next"'
        assert values["cursor"] == [cursor] and values["limit"] == ["100"], values
        tail, tail_headers = self.page(
            "acme", "members", "cursor=" + urllib.parse.quote(cursor, safe=""))
        assert len(tail["items"]) == 1 and tail["truncated"] is False and tail["next_cursor"] is None
        assert "x-next-cursor" not in tail_headers and "link" not in tail_headers
        combined = [item["username"] for item in body["items"] + tail["items"]]
        assert combined == self.expected_members, "default cursor boundary lost or duplicated members"

        teams, team_headers = self.page("acme", "teams")
        assert len(teams["items"]) == 100 and teams["truncated"] is True
        team_tail, _ = self.page(
            "acme", "teams", "cursor=" + urllib.parse.quote(teams["next_cursor"], safe=""))
        assert len(team_tail["items"]) == 1 and team_tail["next_cursor"] is None
        team_slugs = [item["slug"] for item in teams["items"] + team_tail["items"]]
        assert team_slugs == self.expected_teams, "team default boundary lost or duplicated rows"
        assert team_headers["link"]
        return {"members_first_page": len(body["items"]), "members_tail": len(tail["items"]),
                "teams_first_page": len(teams["items"]), "teams_tail": len(team_tail["items"])}

    def bounded_traversal(self):
        members, member_pages = self.walk("acme", "members", 7)
        assert member_pages == 15 and len(members) == 101, (member_pages, len(members))
        assert [item["username"] for item in members] == self.expected_members
        teams, team_pages = self.walk("acme", "teams", 13)
        assert team_pages == 8 and len(teams) == 101, (team_pages, len(teams))
        assert [item["slug"] for item in teams] == self.expected_teams
        widest, _ = self.page("acme", "members", "limit=1000")
        assert len(widest["items"]) == 101 and widest["next_cursor"] is None
        return {"member_pages_at_7": member_pages, "team_pages_at_13": team_pages,
                "unique_members": len({item["username"] for item in members}),
                "unique_teams": len({item["id"] for item in teams})}

    def cursor_contract(self):
        first, headers = self.page("acme", "members", "limit=5")
        cursor = first["next_cursor"]
        assert cursor and cursor == headers["x-next-cursor"]
        assert cursor.isascii() and all(c.isalnum() or c in "-_" for c in cursor), cursor
        quoted = "cursor=" + urllib.parse.quote(cursor, safe="")
        again, _ = self.page("acme", "members", f"limit=5&{quoted}")
        repeat, _ = self.page("acme", "members", f"limit=5&{quoted}")
        assert again["items"] == repeat["items"], "replayed cursor was not deterministic"
        wider, _ = self.page("acme", "members", f"limit=17&{quoted}")
        assert len(wider["items"]) == 17
        assert wider["items"][:5] == again["items"]
        assert not ({item["username"] for item in first["items"]}
                    & {item["username"] for item in wider["items"]}), "cursor replayed returned rows"

        org = self.acme
        scope = self.scope(org, "members")
        user_id = norm(self.alice["user_id"])
        good = f"v1:{len(scope)}:{scope}"
        malformed = {
            "empty": "",
            "garbage": "not-base64!",
            "oversized": "a" * 513,
            "wrong_version": self.encode(f"v2:{len(scope)}:{scope}:1:a:36:{user_id}"),
            "short": self.encode(good),
            "long": self.encode(f"{good}:1:a:36:{user_id}:1:x"),
            "utf8_split": self.encode(f"{good}:1:é"),
            "nul_name": self.encode(f"{good}:1:\x00:36:{user_id}"),
            "invalid_name": self.encode(f"{good}:5:ALICE:36:{user_id}"),
            "nil_uuid": self.encode(f"{good}:5:alice:36:00000000-0000-0000-0000-000000000000"),
            "foreign_scope": self.encode(
                f"v1:{len(scope) + 1}:{scope}x:5:alice:36:{user_id}"),
        }
        for label, raw in malformed.items():
            self.reject("acme", "members", "limit=1&cursor=" + urllib.parse.quote(raw, safe=""))
        self.reject("acme", "teams", "limit=1&cursor=" + urllib.parse.quote(
            self.encode(f"{good}:5:alice:36:{user_id}"), safe=""))
        for query in ("limit=0", "limit=1001", "limit=-1", "limit=abc", "limit=1.5", "bogus=1"):
            self.reject("acme", "members", query)
        assert self.http("/api/orgs/acme/members?limit=1")[0] == 401
        return {"malformed_rejected": len(malformed) + 1, "limits_rejected": 5,
                "unknown_query_rejected": 1}

    def read_only_scope(self):
        first, _ = self.page("acme", "members", "limit=2")
        cursor = first["next_cursor"]
        reader_body, _ = self.page("acme", "members", "limit=2", token=self.reader)
        assert reader_body["items"] == first["items"], "same-user read-only token saw another list"
        resumed, _ = self.page(
            "acme", "members", "limit=2&cursor=" + urllib.parse.quote(cursor, safe=""),
            token=self.reader)
        expected, _ = self.page(
            "acme", "members", "limit=2&cursor=" + urllib.parse.quote(cursor, safe=""))
        assert resumed["items"] == expected["items"], "read-only token could not resume same-user cursor"
        assert self.http("/api/orgs/acme/teams?limit=1", token=self.reader)[0] == 200
        assert self.http("/api/orgs/acme/members/bob", token=self.reader, method="PUT",
                         body={"role": "read"})[0] == 403
        assert self.http("/api/orgs/acme/teams", token=self.reader, method="POST",
                         body={"slug": "reader-team", "name": "reader", "role": "read"})[0] == 403
        return {"listed_members": len(reader_body["items"]), "resumed_with_read_only": True,
                "member_write_rejected": 403, "team_write_rejected": 403}

    def scope_binding(self):
        acme_cursor = self.page("acme", "members", "limit=1")[0]["next_cursor"]
        other, _ = self.doc("/api/orgs", 201, method="POST", body={"slug": "other"})
        self.doc("/api/orgs/acme/members/bob", 201, method="PUT", body={"role": "read"})
        bob_first, _ = self.page("acme", "members", "limit=1", token=self.bob)
        bob_cursor = bob_first["next_cursor"]
        assert bob_cursor and bob_cursor != acme_cursor

        status, _, _ = self.http(
            "/api/orgs/other/members?limit=1&cursor=" + urllib.parse.quote(acme_cursor, safe=""))
        assert status == 400, f"cursor crossed organizations: {status}"
        status, _, _ = self.http(
            "/api/orgs/acme/teams?limit=1&cursor=" + urllib.parse.quote(acme_cursor, safe=""))
        assert status == 400, f"member cursor accepted on teams: {status}"
        team_cursor = self.page("acme", "teams", "limit=1")[0]["next_cursor"]
        status, _, _ = self.http(
            "/api/orgs/acme/members?limit=1&cursor=" + urllib.parse.quote(team_cursor, safe=""))
        assert status == 400, f"team cursor accepted on members: {status}"
        status, _, _ = self.http(
            "/api/orgs/acme/members?limit=1&cursor=" + urllib.parse.quote(bob_cursor, safe=""))
        assert status == 400, f"bob cursor accepted for alice: {status}"

        self.doc("/api/orgs/acme/members/bob", 200, method="DELETE")
        status, _, _ = self.http(
            "/api/orgs/acme/members?limit=1&cursor=" + urllib.parse.quote(bob_cursor, safe=""),
            token=self.bob)
        assert status == 404, f"revoked member resumed an old cursor: {status}"
        assert self.http("/api/orgs/acme/members", token=self.bob)[0] == 404
        return {"cross_org": 400, "cross_kind": 400, "cross_actor": 400,
                "revoked_member_resume": 404, "other_org": other["slug"]}

    def mutation_resume(self):
        first, _ = self.page("acme", "members", "limit=10")
        cursor = first["next_cursor"]
        page_one = [item["username"] for item in first["items"]]
        assert page_one == self.expected_members[:10]
        self.doc("/api/orgs/acme/members/member-050", 200, method="DELETE")
        resumed, pages = self.walk("acme", "members", 50, start=cursor)
        resumed_names = [item["username"] for item in resumed]
        assert pages == 2 and len(resumed_names) == 90, (pages, len(resumed_names))
        assert not (set(page_one) & set(resumed_names)), "cursor replayed an earlier page"
        combined = page_one + resumed_names
        wanted = [name for name in self.expected_members if name != "member-050"]
        assert combined == wanted, "deletion changed keyset position semantics"
        return {"pages_after_cursor": pages, "deleted_absent": True,
                "replayed_rows": 0, "traversed_after_delete": len(combined)}


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
    h = OrganizationPaginationHarness(args)
    success = False
    report = {"binary_sha256": hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
              "source_head": subprocess.run(
                  ["git", "-C", str(Path(__file__).resolve().parents[1]), "rev-parse", "HEAD"],
                  stdout=subprocess.PIPE, check=True).stdout.decode().strip()}
    try:
        for name in ("fixture", "default_boundary", "bounded_traversal",
                     "cursor_contract", "read_only_scope", "scope_binding", "mutation_resume"):
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
            "Membership and team ordering relies on (username,user_id) and (slug,id); renames change position and may be missed by an in-flight traversal.",
            "Concurrent inserts after the cursor appear later; inserts before it are not replayed; deletions simply vanish.",
            "A backup restore that rewinds metadata can leave a cursor outside current rows; clients restart from page one.",
        ])
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
